"""Optional: fills the database with demo sections, subjects, students, attendance and marks
so the dashboards and charts have something to show.   Usage:  python seed_demo.py
Writes demo_credentials.csv (usernames + temporary passwords) next to this file."""
import csv
import os
import random
from datetime import date, datetime, timedelta

import app as A
import db

random.seed(7)
FIRST = ["Arun", "Divya", "Karthik", "Meena", "Surya", "Priya", "Vignesh", "Lakshmi", "Harish", "Nithya",
         "Ganesh", "Keerthi", "Dinesh", "Sandhya", "Prakash", "Revathi"]
LAST = ["Kumar", "Raj", "Devi", "Selvam", "Murugan", "Priya", "Babu", "Sundar"]
SUBJECTS = {"AIDS": ["Machine Learning", "Data Structures", "Statistics"], "CSE": ["Algorithms", "Operating Systems", "DBMS"],
            "IT": ["Web Technology", "Networks", "Cloud Computing"]}


def main():
    A.bootstrap()
    creds = []
    with A.app.app_context():
        depts = {d["code"]: d for d in db.query("SELECT * FROM departments")}
        for code, names in SUBJECTS.items():
            d = depts[code]
            db.execute("INSERT IGNORE INTO sections (department_id, year_no, name) VALUES (%s,2,'A')", (d["id"],))
            for i, n in enumerate(names, 1):
                db.execute("INSERT IGNORE INTO subjects (department_id, year_no, code, name) VALUES (%s,2,%s,%s)",
                           (d["id"], f"{code}20{i}", n))
        stamp = A.now()
        for code in SUBJECTS:
            d = depts[code]
            sec = db.query_one("SELECT id FROM sections WHERE department_id=%s AND year_no=2 AND name='A'", (d["id"],))
            subs = db.query("SELECT id FROM subjects WHERE department_id=%s AND year_no=2", (d["id"],))
            if db.query_one("SELECT id FROM users WHERE role='student' AND department_id=%s AND year_no=2", (d["id"],)):
                continue
            _, fac = A._generate("faculty", d, 1, "demo-seed")
            _, stu = A._generate("student", d, 8, "demo-seed")
            db.commit()
            creds += [(a["username"], a["password"], a["role"]) for a in fac + stu]
            for i, a in enumerate(stu):
                name = f"{FIRST[(i * 3 + len(code)) % len(FIRST)]} {random.choice(LAST)}"
                db.execute("UPDATE users SET name=%s, year_no=2, section_id=%s WHERE id=%s", (name, sec["id"], a["id"]))
                base = random.choice([0.95, 0.88, 0.82, 0.7, 0.62])
                for s in subs:
                    for back in range(14, -1, -1):
                        day = date.today() - timedelta(days=back)
                        if day.weekday() == 6:
                            continue
                        st = "Present" if random.random() < base else "Absent"
                        db.execute("INSERT INTO attendance (student_id, subject_id, att_date, status, method, marked_by, "
                                   "created_at) VALUES (%s,%s,%s,%s,'manual','demo-seed',%s)",
                                   (a["id"], s["id"], day.isoformat(), st, stamp), commit=False)
                    for exam in ("Internal 1", "Internal 2"):
                        db.execute("INSERT INTO marks (student_id, subject_id, exam_type, marks, max_marks, created_at) "
                                   "VALUES (%s,%s,%s,%s,100,%s)",
                                   (a["id"], s["id"], exam, round(random.uniform(28, 96), 1), stamp), commit=False)
            db.commit()
    path = os.path.join(A.BASE, "demo_credentials.csv")
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["username", "temporary_password", "role"])
        w.writerows(creds)
    print(f"Demo data created. Credentials written to {path}")


if __name__ == "__main__":
    main()
