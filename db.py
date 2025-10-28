# db.py
import psycopg2
import psycopg2.extras
import os
from config import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DATABASE_URL

def get_connection():
    # Use DATABASE_URL if available (Railway), otherwise use individual parameters
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL)
    else:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
    # Set autocommit to True to avoid transaction issues with SET SESSION
    conn.autocommit = True
    # Set timezone to Asia/Kolkata for all database operations
    cur = conn.cursor()
    cur.execute("SET SESSION timezone = 'Asia/Kolkata'")
    cur.close()
    # Reset autocommit to False for normal transaction usage
    conn.autocommit = False
    return conn

def dict_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
