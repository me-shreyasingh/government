# GovVerify AI - Backend Server

AI-powered Government Notice Verification System

## Quick Start

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Run the Server
```bash
python app.py
```

Or on Windows, just run:
```bash
..\start-backend.bat
```

The server will start at `http://localhost:5000`

## API Endpoints

### Health Check
```
GET /api/health
```

### Verify Text
```
POST /api/verify/text
Body: { "text": "text to verify" }
```

### Verify File
```
POST /api/verify/file
Body: FormData with 'file' field
```

### Get Statistics
```
GET /api/statistics
```

### Report Issue
```
POST /api/report/issue
Body: {
    "verification_id": "uuid",
    "issue_type": "incorrect_result|new_scam_pattern|technical_problem|other",
    "description": "description"
}
```

### Download Report
```
GET /api/report/download/<verification_id>
```

### Get Demo Samples
```
GET /api/demo/samples
```

## Technologies Used

- **Flask** - Web framework
- **SQLite** - Database
- **NLP** - Natural Language Processing for fraud detection
- **Pattern Matching** - Scam detection patterns

## Project Structure

```
backend/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── govverify.db        # SQLite database (created on first run)
└── uploads/            # Temporary file uploads
```
