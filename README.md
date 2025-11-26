# 🏥 Meditrack - Patient Management System

<div align="center">
  <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Firebase-FFCA28?style=for-the-badge&logo=firebase&logoColor=black" alt="Firebase">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white" alt="Vercel">
</div>

## 📋 Overview

**Meditrack** is a comprehensive patient management system designed to streamline healthcare data management. This backend API provides robust functionality for managing patient records, including personal information, medical metrics, and automated BMI calculations with health categorization.

## ✨ Features

- 🔐 **Secure Patient Management** - Complete CRUD operations for patient records
- 📊 **Automated BMI Calculation** - Real-time BMI computation with health categorization
- 🔍 **Advanced Search & Filtering** - Sort patients by height, weight, or age
- 🌐 **RESTful API** - Clean, well-documented API endpoints
- 🔒 **CORS Enabled** - Secure cross-origin resource sharing
- 📱 **Responsive Design** - Works seamlessly across all devices
- ⚡ **Fast Performance** - Built with FastAPI for optimal speed
- 🔥 **Firebase Integration** - Reliable cloud database storage

## 🚀 Live Applications

<div>

**Visit the live application:** [Meditrack Frontend](https://satyam1120k.github.io/Meditrack_Frontend)

**Visit the live API:** [Meditrack API](https://meditrack-backend-murex.vercel.app)

**API Documentation:** [API Docs](https://meditrack-backend-murex.vercel.app/docs)

</div>

## 🛠️ Tech Stack

### Backend

- **FastAPI** - Modern, fast web framework for building APIs
- **Python 3.x** - Core programming language
- **Firebase** - Cloud database and authentication
- **Pydantic** - Data validation and settings management
- **Uvicorn** - ASGI server implementation

### Deployment

- **Vercel** - Serverless deployment platform
- **GitHub Pages** - Frontend hosting

## 📚 API Endpoints

| Method   | Endpoint                        | Description             |
| -------- | ------------------------------- | ----------------------- |
| `GET`    | `/`                             | API health check        |
| `POST`   | `/auth/signup`                  | Register new user       |
| `POST`   | `/auth/login`                   | Verify user credentials |
| `POST`   | `/patients/`                    | Add new patient         |
| `GET`    | `/patients/viewAll`             | Get all patients        |
| `GET`    | `/patients/view/{patient_id}`   | Get specific patient    |
| `GET`    | `/patients/sort`                | Sort patients by field  |
| `PUT`    | `/patients/update/{patient_id}` | Update patient record   |
| `DELETE` | `/patients/delete/{patient_id}` | Delete patient record   |

## 📊 Patient Data Model

```json
{
  "id": "P001",
  "name": "John Doe",
  "age": 30,
  "gender": "Male",
  "city": "New York",
  "height": 1.75,
  "weight": 70.5,
  "bmi": 23.02,
  "bmi_category": "Normal"
}
```

### BMI Categories

- **Underweight**: BMI < 18.5
- **Normal**: BMI 18.5 - 24.9
- **Overweight**: BMI 25.0 - 29.9
- **Obese**: BMI ≥ 30.0

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Firebase project setup
- Environment variables configured

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/Meditrack_Backend.git
   cd Meditrack_Backend
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**

   ```bash
   # Create .env file with Firebase credentials
   FIREBASE_PROJECT_ID=your_project_id
   FIREBASE_PRIVATE_KEY_ID=your_private_key_id
   FIREBASE_PRIVATE_KEY=your_private_key
   FIREBASE_CLIENT_EMAIL=your_client_email
   FIREBASE_CLIENT_ID=your_client_id
   FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
   FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
   FIREBASE_AUTH_PROVIDER_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
   FIREBASE_CLIENT_CERT_URL=your_client_cert_url
   FIREBASE_DATABASE_URL=your_database_url
   ```

4. **Run the application**

   ```bash
   uvicorn main:app --reload
   ```

5. **Access the API**
   - API: `http://localhost:8000`
   - Documentation: `http://localhost:8000/docs`

## 📖 Usage Examples

### Add a New Patient

```bash
curl -X POST "https://meditrack-backend-murex.vercel.app/patients/" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "P001",
    "name": "John Doe",
    "age": 30,
    "gender": "Male",
    "city": "New York",
    "height": 1.75,
    "weight": 70.5
  }'
```

### Get All Patients

```bash
curl -X GET "https://meditrack-backend-murex.vercel.app/patients/viewAll"
```

### Sort Patients by BMI

### User Signup / Login

```bash
curl -X POST "https://meditrack-backend-murex.vercel.app/auth/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Alice",
    "email": "alice@example.com",
    "password": "StrongPass123"
  }'

curl -X POST "https://meditrack-backend-murex.vercel.app/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "StrongPass123"
  }'
```

```bash
curl -X GET "https://meditrack-backend-murex.vercel.app/patients/sort?sort_by=weight&order_by=desc"
```

## 🔧 Configuration

The application supports CORS for the following origins:

- `https://samir1120k.github.io` (Production frontend)
- `http://localhost:5173` (Development frontend)

## 📁 Project Structure

```
Meditrack_Backend/
├── app/
│   ├── firebase/
│   │   └── service.json
│   ├── firebase_client.py
│   ├── models.py
│   └── patients.py
├── main.py
├── requirements.txt
├── vercel.json
└── README.md
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Satyam Patel**

- GitHub: [@samir1120k](https://github.com/samir1120k)
- Project Link: [Meditrack Backend](https://github.com/samir1120k/Meditrack_Backend)

## 🙏 Acknowledgments

- FastAPI team for the amazing framework
- Firebase for reliable cloud services
- Vercel for seamless deployment
- All contributors and users of this project
