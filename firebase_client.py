"""
firebase_client.py
------------------
Robust Firebase helper supporting Firestore and Realtime Database.

Public API:
  init_firebase(service_account_path, use_realtime=False, realtime_db_url=None, project_id=None, app_name=None)
  push_report(report, collection='url_reports', use_realtime=False)
  get_report(doc_id_or_key, collection='url_reports', use_realtime=False)
  update_report(doc_id_or_key, updates, collection='url_reports', use_realtime=False)
  delete_report(doc_id_or_key, collection='url_reports', use_realtime=False)
  list_reports(limit=50, collection='url_reports', use_realtime=False)

Notes:
 - Requires firebase-admin package installed.
 - init_firebase is safe to call multiple times in the same process.
"""
import time
from typing import Optional, Dict, Any, List
import logging

# Try to import firebase-admin lazily (if it's not installed, functions will raise)
try:
    import firebase_admin
    from firebase_admin import credentials
    from firebase_admin import firestore as _firestore
    from firebase_admin import db as _realtimedb
except Exception:
    firebase_admin = None
    credentials = None
    _firestore = None
    _realtimedb = None

# Logger
logger = logging.getLogger("firebase_client")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Internal state
_STATE = {
    "initialized": False,
    "mode": None,  # 'firestore' or 'realtime'
    "app": None,
    "firestore_client": None,
    "realtime_root": None,
}


def _ensure_firebase_installed():
    if firebase_admin is None:
        raise RuntimeError("firebase-admin is not installed. Install with: pip install firebase-admin")


def init_firebase(
    service_account_path: str,
    use_realtime: bool = False,
    realtime_db_url: Optional[str] = None,
    project_id: Optional[str] = None,
    app_name: Optional[str] = None,
) -> None:
    """
    Initialize firebase admin SDK (idempotent).

    Args:
      - service_account_path: path to service account JSON file (required)
      - use_realtime: if True initialize Realtime DB; otherwise Firestore
      - realtime_db_url: required when use_realtime=True
      - project_id: optional explicit project id
      - app_name: optional Firebase app name when initializing multiple apps
    """
    _ensure_firebase_installed()

    # If already initialized via this module, ensure consistent mode
    if _STATE["initialized"]:
        if use_realtime and _STATE["mode"] != "realtime":
            raise RuntimeError("Firebase already initialized for Firestore. Restart process to re-init as Realtime DB.")
        if (not use_realtime) and _STATE["mode"] != "firestore":
            raise RuntimeError("Firebase already initialized for Realtime DB. Restart process to re-init for Firestore.")
        logger.info("Firebase already initialized (via firebase_client).")
        return

    # If some Firebase app exists in this process (maybe initialized elsewhere), reuse it
    if firebase_admin._apps:
        # reuse default app
        try:
            app = firebase_admin.get_app()
        except Exception:
            # fallback: get arbitrary existing app
            app = next(iter(firebase_admin._apps.values()))
        _STATE["app"] = app
        # attach clients according to desired mode
        if use_realtime:
            if not realtime_db_url:
                # try to initialize realtime root from existing app (may work if DB URL was set earlier)
                _STATE["realtime_root"] = _realtimedb.reference("/", app=app)
                _STATE["mode"] = "realtime"
                logger.info("Reusing existing Firebase app and creating Realtime DB reference.")
            else:
                # if realtime_db_url provided, create a named app to ensure URL binding
                try:
                    cred = credentials.Certificate(service_account_path)
                    name = app_name or "_firebase_client_rt_"
                    # If an app with this name already exists, reuse it
                    if name in firebase_admin._apps:
                        app = firebase_admin.get_app(name)
                    else:
                        app = firebase_admin.initialize_app(cred, {"databaseURL": realtime_db_url}, name=name)
                    _STATE["app"] = app
                    _STATE["realtime_root"] = _realtimedb.reference("/", app=app)
                    _STATE["mode"] = "realtime"
                    logger.info("Initialized (or reused named) Firebase app for Realtime DB.")
                except Exception as e:
                    logger.error("Failed to initialize named Realtime DB app: %s", e)
                    raise
        else:
            # Firestore mode
            try:
                client = _firestore.client(app=app)
                _STATE["firestore_client"] = client
                _STATE["mode"] = "firestore"
                logger.info("Reusing existing Firebase app for Firestore.")
            except Exception as e:
                logger.error("Failed to create Firestore client from existing app: %s", e)
                raise
        _STATE["initialized"] = True
        return

    # No existing app — create one
    cred = credentials.Certificate(service_account_path)
    init_kwargs = {"credential": cred}
    if project_id:
        init_kwargs["project"] = project_id

    try:
        if app_name:
            app = firebase_admin.initialize_app(**init_kwargs, name=app_name)
        else:
            app = firebase_admin.initialize_app(**init_kwargs)
    except TypeError:
        # some firebase_admin versions don't accept 'project' in initialize_app kwargs; fallback
        app = firebase_admin.initialize_app(cred)
    except Exception as e:
        logger.error("Failed to initialize Firebase app: %s", e)
        raise

    _STATE["app"] = app

    if use_realtime:
        if not realtime_db_url:
            raise ValueError("realtime_db_url is required when use_realtime=True")
        # initialize a second app specifically for realtime DB if needed
        try:
            # If the default app was just initialized without DB URL, initialize a named app with DB URL
            # Try to initialize a named app; if name exists, reuse it.
            name = app_name or "_firebase_client_realtime"
            if name in firebase_admin._apps:
                rt_app = firebase_admin.get_app(name)
            else:
                rt_app = firebase_admin.initialize_app(cred, {"databaseURL": realtime_db_url}, name=name)
            _STATE["realtime_root"] = _realtimedb.reference("/", app=rt_app)
            _STATE["mode"] = "realtime"
            logger.info("Initialized Firebase Realtime Database client.")
        except Exception as e:
            logger.error("Failed to initialize Realtime DB app: %s", e)
            raise
    else:
        try:
            client = _firestore.client(app=app)
            _STATE["firestore_client"] = client
            _STATE["mode"] = "firestore"
            logger.info("Initialized Firestore client.")
        except Exception as e:
            logger.error("Failed to initialize Firestore client: %s", e)
            raise

    _STATE["initialized"] = True


# -------------------
# Firestore helpers
# -------------------
def push_report_firestore(report: Dict[str, Any], collection: str = "url_reports") -> str:
    if not _STATE["initialized"] or _STATE["mode"] != "firestore":
        raise RuntimeError("Firestore not initialized. Call init_firebase(..., use_realtime=False) first.")
    client = _STATE["firestore_client"]
    col_ref = client.collection(collection)
    doc_ref = col_ref.document()
    doc_ref.set(report)
    logger.info(f"Pushed report to Firestore: {collection}/{doc_ref.id}")
    return doc_ref.id


def get_report_firestore(doc_id: str, collection: str = "url_reports") -> Optional[Dict[str, Any]]:
    if not _STATE["initialized"] or _STATE["mode"] != "firestore":
        raise RuntimeError("Firestore not initialized.")
    client = _STATE["firestore_client"]
    doc = client.collection(collection).document(doc_id).get()
    return doc.to_dict() if doc.exists else None


def update_report_firestore(doc_id: str, updates: Dict[str, Any], collection: str = "url_reports") -> None:
    if not _STATE["initialized"] or _STATE["mode"] != "firestore":
        raise RuntimeError("Firestore not initialized.")
    client = _STATE["firestore_client"]
    client.collection(collection).document(doc_id).update(updates)
    logger.info(f"Updated Firestore doc {collection}/{doc_id}")


def delete_report_firestore(doc_id: str, collection: str = "url_reports") -> None:
    if not _STATE["initialized"] or _STATE["mode"] != "firestore":
        raise RuntimeError("Firestore not initialized.")
    client = _STATE["firestore_client"]
    client.collection(collection).document(doc_id).delete()
    logger.info(f"Deleted Firestore doc {collection}/{doc_id}")


def list_reports_firestore(limit: int = 50, collection: str = "url_reports") -> List[Dict[str, Any]]:
    if not _STATE["initialized"] or _STATE["mode"] != "firestore":
        raise RuntimeError("Firestore not initialized.")
    client = _STATE["firestore_client"]
    docs = client.collection(collection).limit(limit).stream()
    results = []
    for d in docs:
        entry = d.to_dict()
        entry["_id"] = d.id
        results.append(entry)
    return results


# -------------------
# Realtime DB helpers
# -------------------
def push_report_realtime(report: Dict[str, Any], path: str = "/url_reports") -> str:
    if not _STATE["initialized"] or _STATE["mode"] != "realtime":
        raise RuntimeError("Realtime DB not initialized. Call init_firebase(..., use_realtime=True, realtime_db_url=...) first.")
    root = _STATE["realtime_root"]
    ref = root.child(path)
    new_ref = ref.push(report)
    logger.info(f"Pushed report to RealtimeDB: {path}/{new_ref.key}")
    return new_ref.key


def get_report_realtime(key: str, path: str = "/url_reports") -> Optional[Dict[str, Any]]:
    if not _STATE["initialized"] or _STATE["mode"] != "realtime":
        raise RuntimeError("Realtime DB not initialized.")
    root = _STATE["realtime_root"]
    return root.child(f"{path}/{key}").get()


def update_report_realtime(key: str, updates: Dict[str, Any], path: str = "/url_reports") -> None:
    if not _STATE["initialized"] or _STATE["mode"] != "realtime":
        raise RuntimeError("Realtime DB not initialized.")
    root = _STATE["realtime_root"]
    root.child(f"{path}/{key}").update(updates)
    logger.info(f"Updated RealtimeDB node {path}/{key}")


def delete_report_realtime(key: str, path: str = "/url_reports") -> None:
    if not _STATE["initialized"] or _STATE["mode"] != "realtime":
        raise RuntimeError("Realtime DB not initialized.")
    root = _STATE["realtime_root"]
    root.child(f"{path}/{key}").delete()
    logger.info(f"Deleted RealtimeDB node {path}/{key}")


def list_reports_realtime(path: str = "/url_reports", limit: Optional[int] = None) -> List[Dict[str, Any]]:
    if not _STATE["initialized"] or _STATE["mode"] != "realtime":
        raise RuntimeError("Realtime DB not initialized.")
    root = _STATE["realtime_root"]
    data = root.child(path).get()
    if not data:
        return []
    items = []
    for k, v in (data.items() if isinstance(data, dict) else []):
        entry = v
        if isinstance(entry, dict):
            entry["_key"] = k
        items.append(entry)
    if limit:
        return items[:limit]
    return items


# -------------------
# Unified public API
# -------------------
def push_report(report: Dict[str, Any], collection: str = "url_reports", use_realtime: bool = False) -> str:
    if not _STATE["initialized"]:
        raise RuntimeError("Firebase not initialized. Call init_firebase() first.")
    return push_report_realtime(report, path=f"/{collection}") if use_realtime else push_report_firestore(report, collection=collection)


def get_report(doc_id_or_key: str, collection: str = "url_reports", use_realtime: bool = False) -> Optional[Dict[str, Any]]:
    if not _STATE["initialized"]:
        raise RuntimeError("Firebase not initialized. Call init_firebase() first.")
    return get_report_realtime(doc_id_or_key, path=f"/{collection}") if use_realtime else get_report_firestore(doc_id_or_key, collection=collection)


def update_report(doc_id_or_key: str, updates: Dict[str, Any], collection: str = "url_reports", use_realtime: bool = False) -> None:
    if not _STATE["initialized"]:
        raise RuntimeError("Firebase not initialized. Call init_firebase() first.")
    return update_report_realtime(doc_id_or_key, updates, path=f"/{collection}") if use_realtime else update_report_firestore(doc_id_or_key, updates, collection=collection)


def delete_report(doc_id_or_key: str, collection: str = "url_reports", use_realtime: bool = False) -> None:
    if not _STATE["initialized"]:
        raise RuntimeError("Firebase not initialized. Call init_firebase() first.")
    return delete_report_realtime(doc_id_or_key, path=f"/{collection}") if use_realtime else delete_report_firestore(doc_id_or_key, collection=collection)


def list_reports(limit: int = 50, collection: str = "url_reports", use_realtime: bool = False) -> List[Dict[str, Any]]:
    if not _STATE["initialized"]:
        raise RuntimeError("Firebase not initialized. Call init_firebase() first.")
    return list_reports_realtime(path=f"/{collection}", limit=limit) if use_realtime else list_reports_firestore(limit=limit, collection=collection)


# -------------------
# Helper when run as script for quick testing
# -------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="firebase_client test runner")
    parser.add_argument("--service-account", "-s", required=True, help="Path to Firebase service account JSON file")
    parser.add_argument("--realtime", "-r", action="store_true", help="Use Realtime Database (default: Firestore)")
    parser.add_argument("--realtime-url", help="Realtime DB URL (required if --realtime passed)")
    args = parser.parse_args()

    init_firebase(
        service_account_path=args.service_account,
        use_realtime=args.realtime,
        realtime_db_url=args.realtime_url,
    )

    sample_report = {
        "target": "https://example.com",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {"links_found": 5, "suspicious": 1},
        "details": {"example": "this is a sample report"},
    }

    print("Pushing sample report...")
    id_or_key = push_report(sample_report, collection="url_reports", use_realtime=args.realtime)
    print("Saved with id/key:", id_or_key)

    print("Fetching back...")
    fetched = get_report(id_or_key, collection="url_reports", use_realtime=args.realtime)
    import json as _json
    print(_json.dumps(fetched, indent=2))
