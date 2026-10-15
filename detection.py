from sqlalchemy import select
from sqlalchemy.orm import Session
from main import run_rule
from models import Rule


def run_detection_engine(db:Session):
    print("Checking rule...")
    stmt = select(Rule)
    rules = db.scalars(stmt).all()
    for rule in rules:
        run_rule(rule, db)