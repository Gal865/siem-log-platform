from detection import run_detection_engine
from database import SessionLocal
from time import sleep

while True:
    db = SessionLocal()
    try:
        run_detection_engine(db)
    except Exception as e:
        db.rollback()
        print(e)        
    finally:
        db.close()
    sleep(30)