from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
from pydantic import BaseModel, EmailStr
import logging
import os
import io

from database import init_db, get_db, User
from auth import hash_password, verify_password, create_access_token, get_current_user
import docker_ops
import scenario_runner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Honeypot Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    await init_db()
    logger.info("DB 초기화 완료")


# ── 스키마 ────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime
    deactivated_at: datetime | None

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str
    is_admin: bool


# ── 관리자 의존성 ──────────────────────────────────────────────────────────────

async def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다.")
    return current_user


# ── 인증 ──────────────────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=UserOut, status_code=201)
async def register(body: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    유저 가입 오퍼레이션:
    1. DB에 유저 생성
    2. 해당 유저 전용 허니팟 컨테이너 7종 + 네트워크 생성
    """
    result = await db.execute(select(User).where(User.username == body.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 존재하는 사용자명입니다.")

    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 사용 중인 이메일입니다.")

    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    ops_result = docker_ops.create_user_honeypots(user.username)
    logger.info(f"[register] {user.username} 컨테이너 생성: {ops_result}")

    return user


@app.post("/api/auth/login", response_model=TokenOut)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == form.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 틀렸습니다.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="비활성화된 계정입니다.")

    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "is_admin": user.is_admin}


# ── 유저 관리 ──────────────────────────────────────────────────────────────────

@app.get("/api/users/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/api/users", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_admin_user),
):
    """관리자 전용: 전체 유저 목록."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@app.delete("/api/users/{user_id}", status_code=204)
async def deactivate_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_admin_user),
):
    """
    관리자 전용 - 유저 비활성화 오퍼레이션:
    1. DB 유저 비활성화
    2. 해당 유저 전용 컨테이너 + 네트워크 삭제
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="유저를 찾을 수 없습니다.")
    if user.is_admin:
        raise HTTPException(status_code=400, detail="관리자 계정은 비활성화할 수 없습니다.")

    username = user.username
    user.is_active = False
    user.deactivated_at = datetime.utcnow()
    await db.commit()

    ops_result = docker_ops.remove_user_honeypots(username)
    logger.info(f"[deactivate] {username} 컨테이너 정리: {ops_result}")


@app.post("/api/users/{user_id}/activate", response_model=UserOut)
async def activate_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_admin_user),
):
    """
    관리자 전용 - 유저 재활성화 오퍼레이션:
    1. DB 유저 활성화
    2. 해당 유저 전용 컨테이너 재생성
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="유저를 찾을 수 없습니다.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="이미 활성 상태입니다.")

    user.is_active = True
    user.deactivated_at = None
    await db.commit()
    await db.refresh(user)

    ops_result = docker_ops.create_user_honeypots(user.username)
    logger.info(f"[activate] {user.username} 컨테이너 재생성: {ops_result}")

    return user


# ── 컨테이너 상태 ──────────────────────────────────────────────────────────────

@app.get("/api/containers")
async def get_my_containers(current_user: User = Depends(get_current_user)):
    """현재 유저의 컨테이너 상태 조회."""
    return docker_ops.get_user_container_status(current_user.username)


@app.get("/api/admin/containers")
async def get_all_containers(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_admin_user),
):
    """관리자 전용: 모든 유저의 컨테이너 상태를 유저별로 반환."""
    result = await db.execute(select(User).where(User.is_active == True, User.is_admin == False))
    active_users = result.scalars().all()
    usernames = [u.username for u in active_users]
    return docker_ops.get_all_users_container_status(usernames)


@app.post("/api/containers/{container_name}/{action}")
async def control_container(
    container_name: str,
    action: str,
    _: User = Depends(get_admin_user),
):
    """관리자 전용: 개별 컨테이너 start / stop / restart."""
    if action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="action은 start/stop/restart 중 하나여야 합니다.")
    return docker_ops.control_container(container_name, action)


@app.get("/api/containers/{container_name}/logs")
async def get_logs(container_name: str, tail: int = 100, _: User = Depends(get_admin_user)):
    """관리자 전용: 컨테이너 로그 조회."""
    logs = docker_ops.get_container_logs(container_name, tail=tail)
    if logs is None:
        raise HTTPException(status_code=404, detail="컨테이너를 찾을 수 없습니다.")
    return {"name": container_name, "logs": logs}


# ── 공격 시나리오 ──────────────────────────────────────────────────────────────

@app.get("/api/scenarios")
async def list_scenarios(current_user: User = Depends(get_current_user)):
    """현재 유저의 시나리오 목록 + 실행 상태 조회."""
    return scenario_runner.get_user_status(current_user.username)


@app.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str, current_user: User = Depends(get_current_user)):
    """시나리오 실행 (유저 본인 허니팟 대상)."""
    result = scenario_runner.run_scenario(scenario_id, current_user.username)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str, current_user: User = Depends(get_current_user)):
    """특정 시나리오 상태 + 출력 조회."""
    status = scenario_runner.get_scenario_status(current_user.username, scenario_id)
    if not status:
        raise HTTPException(status_code=404, detail="존재하지 않는 시나리오입니다.")
    return status


@app.get("/api/admin/scenarios")
async def list_all_scenarios(_: User = Depends(get_admin_user)):
    """관리자 전용: 전체 유저 시나리오 현황."""
    return scenario_runner.get_all_users_status()


# ── 시나리오 히스토리 ──────────────────────────────────────────────────────────

@app.get("/api/history")
async def get_history(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """현재 유저의 시나리오 실행 이력 (최신순)."""
    from sqlalchemy import desc
    from database import ScenarioRun
    result = await db.execute(
        select(ScenarioRun)
        .where(ScenarioRun.username == current_user.username)
        .order_by(desc(ScenarioRun.finished_at))
        .limit(limit)
    )
    runs = result.scalars().all()
    return [
        {
            "id":            r.id,
            "scenario_id":   r.scenario_id,
            "scenario_name": r.scenario_name,
            "label":         r.label,
            "state":         r.state,
            "started_at":    r.started_at.isoformat() if r.started_at else None,
            "finished_at":   r.finished_at.isoformat() if r.finished_at else None,
            "output":        r.output,
        }
        for r in runs
    ]


@app.get("/api/admin/stats")
async def get_admin_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_admin_user),
):
    """관리자 전용: 유저별 데이터셋 현황 + 시나리오 집계."""
    import json as json_mod
    from collections import defaultdict
    from database import ScenarioRun
    from sqlalchemy import func

    # 활성 일반 유저 목록
    result = await db.execute(
        select(User).where(User.is_active == True, User.is_admin == False)
    )
    users = result.scalars().all()

    # 유저별 시나리오 실행 집계
    run_result = await db.execute(
        select(ScenarioRun.username, ScenarioRun.state, func.count().label("cnt"))
        .group_by(ScenarioRun.username, ScenarioRun.state)
    )
    runs_raw = run_result.all()
    run_stats: dict[str, dict] = defaultdict(lambda: {"done": 0, "failed": 0, "total": 0})
    for username, state, cnt in runs_raw:
        run_stats[username][state] = cnt
        run_stats[username]["total"] += cnt

    # 유저별 데이터셋 파일 현황
    user_stats = []
    for u in users:
        meta_path = os.path.join(LOGS_HOST_ROOT, u.username, "dataset_meta.json")
        dataset_info = None
        if os.path.exists(meta_path):
            try:
                with open(meta_path, encoding="utf-8") as f:
                    m = json_mod.load(f)
                dataset_info = {
                    "row_count":    m.get("row_count", 0),
                    "generated_at": m.get("dataset_version", ""),
                    "size":         os.path.getsize(os.path.join(LOGS_HOST_ROOT, u.username, "dataset.csv"))
                                    if os.path.exists(os.path.join(LOGS_HOST_ROOT, u.username, "dataset.csv")) else 0,
                }
            except Exception:
                pass

        rs = run_stats[u.username]
        user_stats.append({
            "username":    u.username,
            "created_at":  u.created_at.isoformat(),
            "dataset":     dataset_info,
            "runs_done":   rs["done"],
            "runs_failed": rs["failed"],
            "runs_total":  rs["total"],
        })

    return user_stats


@app.get("/api/admin/history")
async def get_all_history(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_admin_user),
):
    """관리자 전용: 전체 유저 시나리오 실행 이력."""
    from sqlalchemy import desc
    from database import ScenarioRun
    result = await db.execute(
        select(ScenarioRun)
        .order_by(desc(ScenarioRun.finished_at))
        .limit(limit)
    )
    runs = result.scalars().all()
    return [
        {
            "id":            r.id,
            "username":      r.username,
            "scenario_id":   r.scenario_id,
            "scenario_name": r.scenario_name,
            "label":         r.label,
            "state":         r.state,
            "started_at":    r.started_at.isoformat() if r.started_at else None,
            "finished_at":   r.finished_at.isoformat() if r.finished_at else None,
        }
        for r in runs
    ]


# ── WebSocket 실시간 로그 스트리밍 ────────────────────────────────────────────

@app.websocket("/ws/logs/{container_name}")
async def stream_logs(websocket: WebSocket, container_name: str, token: str = ""):
    """
    컨테이너 로그 실시간 스트리밍.
    blocking Docker 스트림을 스레드 executor에서 실행해 이벤트 루프를 보호한다.
    """
    import asyncio
    import queue
    import threading
    import docker as docker_sdk
    from jose import JWTError, jwt
    from auth import SECRET_KEY, ALGORITHM

    # JWT 검증
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    log_queue: queue.Queue = queue.Queue(maxsize=200)
    stop_event = threading.Event()

    def _stream_worker():
        try:
            client = docker_sdk.from_env()
            container = client.containers.get(container_name)
            for chunk in container.logs(stream=True, follow=True, timestamps=True, tail=50):
                if stop_event.is_set():
                    break
                line = chunk.decode("utf-8", errors="replace").strip()
                if line:
                    try:
                        log_queue.put(line, timeout=1)
                    except queue.Full:
                        pass
        except Exception as e:
            try:
                log_queue.put(f"[오류] {e}", timeout=1)
            except queue.Full:
                pass
        finally:
            log_queue.put(None)  # 종료 신호

    t = threading.Thread(target=_stream_worker, daemon=True)
    t.start()

    try:
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: log_queue.get(timeout=2)
                )
            except queue.Empty:
                continue

            if line is None:
                break

            try:
                await websocket.send_text(line)
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(f"[오류] {e}")
        except Exception:
            pass
    finally:
        stop_event.set()
        try:
            await websocket.close()
        except Exception:
            pass


# ── 데이터셋 생성 / 다운로드 ───────────────────────────────────────────────────

LOGS_HOST_ROOT = "/mnt/d/honeypot_logs"  # 백엔드(Linux/WSL)에서 접근하는 호스트 경로


def _user_dataset_path(username: str, filename: str) -> str:
    return os.path.join(LOGS_HOST_ROOT, username, filename)


@app.post("/api/dataset/generate")
async def generate_dataset(current_user: User = Depends(get_current_user)):
    """
    유저 전용 허니팟 로그를 파싱해 dataset.csv를 생성한다.
    kali-attacker 컨테이너 내부에서 parse_logs.py --user {username} 실행.
    """
    import asyncio
    import docker as docker_sdk

    username = current_user.username
    try:
        client = docker_sdk.from_env()
        kali = client.containers.get("kali-attacker")

        if kali.status != "running":
            kali.start()
            kali.reload()

        def _run():
            exit_code, output = kali.exec_run(
                cmd=["python3", "/scripts/parse_logs.py", "--user", username],
                stdout=True,
                stderr=True,
                stream=False,
            )
            decoded = output.decode("utf-8", errors="replace") if output else ""
            return exit_code, decoded

        loop = asyncio.get_event_loop()
        exit_code, output = await loop.run_in_executor(None, _run)

        if exit_code != 0:
            raise HTTPException(status_code=500, detail=f"파싱 실패 (exit={exit_code}): {output[-500:]}")

        # 생성된 파일 크기 확인
        csv_path = _user_dataset_path(username, "dataset.csv")
        size = os.path.getsize(csv_path) if os.path.exists(csv_path) else 0

        return {"status": "ok", "exit_code": exit_code, "rows_hint": output.strip().split("\n")[-3:], "csv_size": size}

    except docker_sdk.errors.NotFound:
        raise HTTPException(status_code=503, detail="kali-attacker 컨테이너를 찾을 수 없습니다.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/dataset/status")
async def dataset_status(current_user: User = Depends(get_current_user)):
    """유저의 데이터셋 파일 존재 여부 및 크기 반환."""
    username = current_user.username
    files = {}
    for fname in ("dataset.csv", "dataset_meta.json"):
        path = _user_dataset_path(username, fname)
        if os.path.exists(path):
            stat = os.stat(path)
            files[fname] = {"exists": True, "size": stat.st_size, "mtime": stat.st_mtime}
        else:
            files[fname] = {"exists": False, "size": 0, "mtime": None}
    return files


@app.get("/api/dataset/download")
async def download_dataset(
    filename: str = "dataset.csv",
    current_user: User = Depends(get_current_user),
):
    """유저의 dataset.csv 또는 dataset_meta.json 다운로드."""
    if filename not in ("dataset.csv", "dataset_meta.json"):
        raise HTTPException(status_code=400, detail="허용되지 않는 파일명입니다.")

    username = current_user.username
    path = _user_dataset_path(username, filename)

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="파일이 없습니다. 먼저 데이터셋을 생성하세요.")

    media_type = "text/csv" if filename.endswith(".csv") else "application/json"
    return FileResponse(
        path=path,
        media_type=media_type,
        filename=f"{username}_{filename}",
    )


@app.get("/api/stats")
async def get_stats(current_user: User = Depends(get_current_user)):
    """
    유저의 dataset_meta.json + dataset.csv를 읽어 차트용 통계 반환.
    meta가 없으면 404.
    """
    import json
    import csv as csv_mod
    from collections import defaultdict

    username = current_user.username
    meta_path = _user_dataset_path(username, "dataset_meta.json")
    csv_path  = _user_dataset_path(username, "dataset.csv")

    if not os.path.exists(meta_path):
        raise HTTPException(status_code=404, detail="데이터셋을 먼저 생성하세요.")

    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)

    # 시간대별 이벤트 수 (dataset.csv에서 집계)
    timeline = []
    if os.path.exists(csv_path):
        hourly: dict[str, int] = defaultdict(int)
        with open(csv_path, encoding="utf-8") as f:
            reader = csv_mod.DictReader(f)
            for row in reader:
                ts = row.get("timestamp", "")
                if len(ts) >= 13:          # "2026-04-14T08"
                    hour_key = ts[:13].replace("T", " ")
                    hourly[hour_key] += 1
        timeline = [{"hour": h, "count": c} for h, c in sorted(hourly.items())]

    return {
        "row_count":   meta.get("row_count", 0),
        "generated_at": meta.get("dataset_version", ""),
        "distributions": meta.get("distributions", {}),
        "timeline": timeline,
    }
