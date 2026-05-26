# SecureCC: Advanced Secure Compiler Environment

**SecureCC** is a security-aware development environment designed to detect and prevent vulnerabilities in C code during the compilation process. It uses a custom lexical and syntax analysis engine to provide real-time feedback on memory safety, injection risks, and insecure coding patterns.

---

## 🚀 Getting Started

### 1. Prerequisites
- **Python 3.10+** (Required for the analysis backend)
- **Node.js 18+** (Required for the React frontend)
- **GCC / MinGW** (Required for secure compilation)

### 2. Backend Setup (FastAPI)
Navigate to the `backend` directory and initialize the environment:
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Frontend Setup (React)
Navigate to the `frontend` directory and install dependencies:
```powershell
cd frontend
npm install
```

---

## 🛠 Running the Project

### One-Click Launch (Windows)
In the project root, simply run:
```powershell
.\run_backend.bat
```
Then, in a separate terminal:
```powershell
cd frontend
npm start
```

Your environment will be available at **http://localhost:3000**.

---

## 🛡 Vulnerability Detection Capabilities
SecureCC currently detects:
- **Buffer Overflows**: Unsafe string and input functions (`gets`, `strcpy`, etc.).
- **Memory Safety**: Use-After-Free, Double Free, and Unchecked memory returns.
- **Injections**: Command Injection (`system`, `popen`) and Format String vulnerabilities.
- **Cryptographic Risks**: Weak randomness (`rand`) and insecure hashing (`md5`).
- **Permissions**: Insecure file permissions (`chmod 777`).

---

## 📂 Project Structure
- `backend/`: FastAPI server and API endpoints.
- `compiler/`: Custom PEG-based lexical and syntax analyzer.
- `frontend/`: React-based IDE with Monaco Editor integration.

---

## ⚖ License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
