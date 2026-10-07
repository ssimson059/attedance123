CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(100) NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  last_login DATETIME NULL,
  created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS departments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(10) NOT NULL UNIQUE,
  name VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS sections (
  id INT AUTO_INCREMENT PRIMARY KEY,
  department_id INT NOT NULL,
  year_no INT NOT NULL,
  name VARCHAR(10) NOT NULL,
  UNIQUE (department_id, year_no, name),
  FOREIGN KEY (department_id) REFERENCES departments(id)
);

CREATE TABLE IF NOT EXISTS subjects (
  id INT AUTO_INCREMENT PRIMARY KEY,
  department_id INT NOT NULL,
  year_no INT NOT NULL,
  code VARCHAR(20) NOT NULL UNIQUE,
  name VARCHAR(120) NOT NULL,
  FOREIGN KEY (department_id) REFERENCES departments(id)
);

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  role VARCHAR(10) NOT NULL,
  department_id INT NOT NULL,
  year_no INT NULL,
  section_id INT NULL,
  username VARCHAR(40) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  status VARCHAR(10) NOT NULL DEFAULT 'active',
  must_change_password TINYINT NOT NULL DEFAULT 1,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  last_login DATETIME NULL,
  created_at DATETIME NOT NULL,
  created_by VARCHAR(50) NOT NULL,
  FOREIGN KEY (department_id) REFERENCES departments(id),
  FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS sequences (
  role VARCHAR(10) NOT NULL,
  dept_code VARCHAR(10) NOT NULL,
  last_no INT NOT NULL DEFAULT 0,
  PRIMARY KEY (role, dept_code)
);

CREATE TABLE IF NOT EXISTS generation_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  batch_id VARCHAR(20) NOT NULL,
  user_id INT NULL,
  username VARCHAR(40) NOT NULL,
  role VARCHAR(10) NOT NULL,
  department_code VARCHAR(10) NOT NULL,
  generated_by VARCHAR(50) NOT NULL,
  generated_at DATETIME NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attendance (
  id INT AUTO_INCREMENT PRIMARY KEY,
  student_id INT NOT NULL,
  subject_id INT NOT NULL,
  att_date DATE NOT NULL,
  status VARCHAR(10) NOT NULL,
  method VARCHAR(10) NOT NULL DEFAULT 'manual',
  marked_by VARCHAR(50) NOT NULL,
  created_at DATETIME NOT NULL,
  UNIQUE (student_id, subject_id, att_date),
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS marks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  student_id INT NOT NULL,
  subject_id INT NOT NULL,
  exam_type VARCHAR(30) NOT NULL,
  marks DECIMAL(5,2) NOT NULL,
  max_marks DECIMAL(5,2) NOT NULL DEFAULT 100,
  created_at DATETIME NOT NULL,
  UNIQUE (student_id, subject_id, exam_type),
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  actor VARCHAR(50) NOT NULL,
  action VARCHAR(60) NOT NULL,
  detail VARCHAR(255) NULL,
  created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS class_sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  faculty_id INT NOT NULL,
  subject_id INT NOT NULL,
  department_id INT NOT NULL,
  year_no INT NOT NULL,
  section_id INT NOT NULL,
  att_date DATE NOT NULL,
  secret VARCHAR(64) NOT NULL,
  started_at DATETIME NOT NULL,
  ends_at DATETIME NOT NULL,
  closed_at DATETIME NULL,
  status VARCHAR(10) NOT NULL DEFAULT 'open',
  lat DOUBLE NULL,
  lon DOUBLE NULL,
  radius_m INT NULL,
  faculty_ip VARCHAR(45) NULL,
  FOREIGN KEY (faculty_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE,
  FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS session_marks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  session_id INT NOT NULL,
  student_id INT NOT NULL,
  device_hash VARCHAR(64) NOT NULL,
  distance_m INT NULL,
  marked_at DATETIME NOT NULL,
  UNIQUE (session_id, student_id),
  UNIQUE (session_id, device_hash),
  FOREIGN KEY (session_id) REFERENCES class_sessions(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS student_devices (
  student_id INT NOT NULL PRIMARY KEY,
  device_hash VARCHAR(64) NOT NULL UNIQUE,
  bound_at DATETIME NOT NULL,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS presence_state (
  session_id INT NOT NULL,
  student_id INT NOT NULL,
  device_hash VARCHAR(64) NULL,
  first_ok_ts DOUBLE NULL,
  last_ts DOUBLE NOT NULL,
  ok_count INT NOT NULL DEFAULT 0,
  same_count INT NOT NULL DEFAULT 0,
  jitter_count INT NOT NULL DEFAULT 0,
  last_lat DOUBLE NULL,
  last_lon DOUBLE NULL,
  score INT NOT NULL DEFAULT 0,
  decision VARCHAR(10) NOT NULL DEFAULT 'pending',
  reasons VARCHAR(400) NULL,
  review VARCHAR(10) NULL,
  PRIMARY KEY (session_id, student_id),
  FOREIGN KEY (session_id) REFERENCES class_sessions(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS presence_flags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  session_id INT NOT NULL,
  student_id INT NOT NULL,
  kind VARCHAR(30) NOT NULL,
  detail VARCHAR(200) NULL,
  created_at DATETIME NOT NULL,
  UNIQUE (session_id, student_id, kind),
  FOREIGN KEY (session_id) REFERENCES class_sessions(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);
