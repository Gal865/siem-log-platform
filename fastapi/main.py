from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI()

class Log(BaseModel):
    ip: str
    username: str
    action: str

logs = [
    {
        "id": 1,
        "ip": "192.168.1.5",
        "username": "john",
        "action": "failed_login"
    },
    {
        "id": 2,
        "ip": "10.0.0.8",
        "username": "admin",
        "action": "login"
    }
]

@app.get("/")
def root():
    return {"message": "SIEM API running"}

@app.get("/logs")
def get_logs():
    return logs

@app.get("/logs/{log_id}")
def get_log(log_id: int):
    for log in logs:
        if log["id"] == log_id:
            return log

    raise HTTPException(
        status_code=404,
        detail="Log not found"
    )

@app.get("/search")
def search_logs(action: str | None = None):

    results = []

    for log in logs:

        if action is None or log["action"] == action:
            results.append(log)

    return results

@app.post("/logs")
def create_log(log: Log):

    new_log = {
        "id": len(logs) + 1,
        "ip": log.ip,
        "username": log.username,
        "action": log.action
    }

    logs.append(new_log)
    return new_log