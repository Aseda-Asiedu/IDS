from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# SQLite database file path
SQLALCHEMY_DATABASE_URL = "sqlite:///./backend/app_v2.db"

# Ensure the backend folder exists
os.makedirs("./backend", exist_ok=True)

# Create the SQLite engine. 
# check_same_thread=False is required for SQLite in FastAPI because multiple threads will access it.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def run_db_migrations():
    from sqlalchemy import text
    try:
        with engine.begin() as conn:
            # 1. Traffic logs migrations
            res = conn.execute(text("PRAGMA table_info(traffic_logs);")).fetchall()
            columns = [r[1] for r in res]
            if columns and "import_batch_id" not in columns:
                conn.execute(text("ALTER TABLE traffic_logs ADD COLUMN import_batch_id INTEGER;"))
            if columns and "source" not in columns:
                conn.execute(text("ALTER TABLE traffic_logs ADD COLUMN source VARCHAR(100) DEFAULT 'live';"))
            if columns and "connection_state" not in columns:
                conn.execute(text("ALTER TABLE traffic_logs ADD COLUMN connection_state VARCHAR(50) DEFAULT 'N/A';"))
                
            # 2. Alerts migrations
            res_a = conn.execute(text("PRAGMA table_info(alerts);")).fetchall()
            a_cols = [r[1] for r in res_a]
            if a_cols and "import_batch_id" not in a_cols:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN import_batch_id INTEGER;"))
            if a_cols and "device_id" not in a_cols:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN device_id INTEGER;"))
            if a_cols and "alert_type" not in a_cols:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN alert_type VARCHAR(50) DEFAULT 'flow_classification';"))
    except Exception as e:
        print(f"Database migration notice: {e}")

# Run schema migrations on module initialization
run_db_migrations()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

