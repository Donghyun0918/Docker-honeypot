"""
Docker SDK를 이용한 유저별 허니팟 컨테이너 제어 모듈.
유저 가입 시 전용 컨테이너 세트 생성, 비활성화 시 해당 컨테이너만 정리한다.
"""
import docker
import logging
from typing import Optional

logger = logging.getLogger(__name__)

PROJECT_ROOT = "/mnt/d/docker_honeypot"
LOGS_ROOT = "/mnt/d/honeypot_logs"

# docker compose build 결과 이미지명 (프로젝트명: docker_honeypot)
HONEYPOT_IMAGES = {
    "cowrie":    "cowrie/cowrie:latest",
    "heralding": "honeypot-heralding",
    "opencanary":"honeypot-opencanary",
    "tanner":    "honeypot-tanner",
    "snare":     "honeypot-snare",
    "dionaea":   "dinotools/dionaea:latest",
    "mailoney":  "honeypot-mailoney",
    "conpot":    "honeypot-conpot",
}


def get_client() -> docker.DockerClient:
    return docker.from_env()


def container_name(username: str, honeypot: str) -> str:
    return f"hp_{username}_{honeypot}"


def network_name(username: str) -> str:
    return f"hp_net_{username}"


def _honeypot_run_kwargs(username: str, honeypot: str) -> dict:
    """허니팟 종류별 컨테이너 실행 옵션 반환."""
    log_dir = f"{LOGS_ROOT}/{username}/{honeypot}"
    cfg = PROJECT_ROOT

    base = {
        "detach": True,
        "restart_policy": {"Name": "unless-stopped"},
    }

    if honeypot == "cowrie":
        return {**base,
            "volumes": {
                f"{cfg}/honeypots/cowrie/cowrie.cfg": {"bind": "/cowrie/cowrie-git/etc/cowrie.cfg", "mode": "ro"},
                f"{cfg}/honeypots/cowrie/userdb.txt": {"bind": "/cowrie/cowrie-git/etc/userdb.txt", "mode": "ro"},
                log_dir: {"bind": "/tmp/cowrie_logs", "mode": "rw"},
            },
            "cap_add": ["NET_BIND_SERVICE"],
        }

    if honeypot == "heralding":
        return {**base,
            "volumes": {
                log_dir: {"bind": "/var/log/heralding", "mode": "rw"},
            },
        }

    if honeypot == "opencanary":
        return {**base,
            "command": "sh -c 'rm -f /root/twistd.pid /tmp/twistd.pid && opencanaryd --dev'",
            "volumes": {
                f"{cfg}/honeypots/opencanary/opencanary.conf": {"bind": "/root/.opencanary.conf", "mode": "ro"},
                log_dir: {"bind": "/var/log/opencanary", "mode": "rw"},
            },
        }

    if honeypot == "snare":
        tanner_host = container_name(username, "tanner")
        return {**base,
            "command": f"snare --port 8080 --host-ip 0.0.0.0 --page-dir /snare/pages/example.com --tanner {tanner_host}",
            "volumes": {
                log_dir: {"bind": "/opt/snare", "mode": "rw"},
            },
        }

    if honeypot == "dionaea":
        return {**base,
            "volumes": {
                f"{cfg}/honeypots/dionaea/dionaea.cfg": {"bind": "/etc/dionaea/dionaea.cfg", "mode": "ro"},
                log_dir: {"bind": "/opt/dionaea/var/log/dionaea", "mode": "rw"},
            },
            "cap_add": ["NET_BIND_SERVICE"],
        }

    if honeypot == "mailoney":
        return {**base,
            "volumes": {
                log_dir: {"bind": "/var/log/mailoney", "mode": "rw"},
            },
        }

    if honeypot == "conpot":
        return {**base,
            "volumes": {
                log_dir: {"bind": "/var/log/conpot", "mode": "rw"},
            },
        }

    return base


def create_user_honeypots(username: str) -> dict:
    """
    유저 가입 오퍼레이션:
    유저 전용 네트워크 + 허니팟 컨테이너 7종 생성.
    """
    import os
    client = get_client()
    results = {}

    # 로그 디렉토리 생성
    for hp in HONEYPOT_IMAGES:
        os.makedirs(f"{LOGS_ROOT}/{username}/{hp}", exist_ok=True)

    # 전용 네트워크 생성
    net = network_name(username)
    try:
        client.networks.get(net)
        results["network"] = "already_exists"
    except docker.errors.NotFound:
        client.networks.create(net, driver="bridge")
        results["network"] = "created"
        logger.info(f"[create] 네트워크 생성: {net}")

    # 허니팟 컨테이너 생성
    for hp, image in HONEYPOT_IMAGES.items():
        name = container_name(username, hp)
        try:
            # 이미 존재하면 시작만
            existing = client.containers.get(name)
            if existing.status != "running":
                existing.start()
            results[hp] = "started_existing"
            continue
        except docker.errors.NotFound:
            pass

        try:
            kwargs = _honeypot_run_kwargs(username, hp)
            container = client.containers.run(
                image,
                name=name,
                network=net,
                **kwargs,
            )
            results[hp] = f"created:{container.short_id}"
            logger.info(f"[create] {name} 생성 완료")
        except Exception as e:
            results[hp] = f"error:{e}"
            logger.error(f"[create] {name} 실패: {e}")

    return results


def remove_user_honeypots(username: str) -> dict:
    """
    유저 비활성화 오퍼레이션:
    해당 유저의 컨테이너 + 네트워크만 정지 및 삭제.
    """
    client = get_client()
    results = {}

    for hp in HONEYPOT_IMAGES:
        name = container_name(username, hp)
        try:
            container = client.containers.get(name)
            container.stop(timeout=10)
            container.remove()
            results[hp] = "removed"
            logger.info(f"[remove] {name} 삭제 완료")
        except docker.errors.NotFound:
            results[hp] = "not_found"
        except Exception as e:
            results[hp] = f"error:{e}"
            logger.error(f"[remove] {name} 실패: {e}")

    # 네트워크 삭제
    net = network_name(username)
    try:
        network = client.networks.get(net)
        network.remove()
        results["network"] = "removed"
        logger.info(f"[remove] 네트워크 {net} 삭제 완료")
    except docker.errors.NotFound:
        results["network"] = "not_found"
    except Exception as e:
        results["network"] = f"error:{e}"

    return results


def get_user_container_status(username: str) -> list[dict]:
    """유저 전용 컨테이너 상태 목록 반환."""
    client = get_client()
    statuses = []
    for hp in HONEYPOT_IMAGES:
        name = container_name(username, hp)
        try:
            c = client.containers.get(name)
            statuses.append({
                "name": name,
                "honeypot": hp,
                "username": username,
                "status": c.status,
                "id": c.short_id,
            })
        except docker.errors.NotFound:
            statuses.append({
                "name": name,
                "honeypot": hp,
                "username": username,
                "status": "not_found",
                "id": None,
            })
        except Exception as e:
            statuses.append({
                "name": name,
                "honeypot": hp,
                "username": username,
                "status": "error",
                "id": None,
            })
    return statuses


def get_all_users_container_status(usernames: list[str]) -> dict[str, list]:
    """관리자용: 모든 유저의 컨테이너 상태를 유저별로 반환."""
    return {username: get_user_container_status(username) for username in usernames}


def control_container(name: str, action: str) -> dict:
    """
    개별 컨테이너 제어.
    action: start | stop | restart
    """
    client = get_client()
    try:
        container = client.containers.get(name)
        if action == "start":
            container.start()
        elif action == "stop":
            container.stop(timeout=10)
        elif action == "restart":
            container.restart(timeout=10)
        else:
            return {"name": name, "action": action, "result": "unknown_action"}

        container.reload()
        logger.info(f"[control] {action} {name} → {container.status}")
        return {"name": name, "action": action, "result": "ok", "status": container.status}
    except docker.errors.NotFound:
        return {"name": name, "action": action, "result": "not_found"}
    except Exception as e:
        logger.error(f"[control] {action} {name}: {e}")
        return {"name": name, "action": action, "result": f"error:{e}"}


def get_container_logs(container_name_str: str, tail: int = 100) -> Optional[str]:
    """컨테이너 최근 로그 조회."""
    try:
        client = get_client()
        container = client.containers.get(container_name_str)
        return container.logs(tail=tail, timestamps=True).decode("utf-8", errors="replace")
    except docker.errors.NotFound:
        return None
    except Exception as e:
        logger.error(f"[logs] {container_name_str}: {e}")
        return None
