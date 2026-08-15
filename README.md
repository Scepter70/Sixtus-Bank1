# 💎 Sixtus Bank

A premium multi-currency banking platform built with **Streamlit**. Features animated backgrounds, glassmorphism UI, real-time currency exchange, and secure PBKDF2-SHA256 password hashing.

![Sixtus Bank](https://img.shields.io/badge/Sixtus-Bank-gold?style=for-the-badge)
![Streamlit](https://img.shields.io/badge/Built%20with-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit)
![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python)

---

## ✨ Features

- 🎨 **Animated Mesh Gradient Background** with floating gold particles
- 🔮 **Glassmorphism UI** with shimmer borders and hover effects
- 💰 **Multi-Currency Wallets** — USD, EUR, GBP, CAD, AUD, CHF, JPY, NGN
- 🔄 **Instant Currency Exchange** with transparent rates
- 🔒 **PBKDF2-SHA256 Encryption** (120,000 rounds)
- 👤 **Customer & Admin Dashboards**
- 📊 **Transaction History & Analytics**
- 📱 **Responsive Design**

---

## 🚀 Deploy on Streamlit Cloud

1. Fork or create a repo with `app.py` and `requirements.txt`
2. Visit [share.streamlit.io](https://share.streamlit.io/)
3. Click **New app** → Select your repo → File: `app.py` → **Deploy**

---

## 🔐 First-Time Setup

On first launch, the app requires you to **create the administrator account**.  
No hardcoded credentials exist in the source code.

1. Open the deployed app
2. Fill in the **Initial Setup** form:
   - Full Name
   - Username
   - Password (minimum 8 characters)
   - Confirm Password
3. Sign in with your new admin credentials
4. Customers can self-register via the **Create Account** tab

5. License
Copyright © 2026 Chetachukwu Sixtus Obiorah.
All Rights Reserved.
This project is proprietary.
Unauthorized copying, modification, distribution, or commercial use of this software is strictly prohibited without prior written permission from the author.
For licensing, collaboration, or purchase inquiries, please contact:
sixtusobiorah70@gmail.com
Note: The RarePlanes dataset is available under its own separate license terms (see cosmiqworks.org) and is not covered by the proprietary license above.
Author
Chetachukwu Sixtus Obiorah
Computer Science Student | Aspiring Software Developer
GitHub: Scepter70

---

## 🛠️ Local Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/sixtus-bank.git
cd sixtus-bank

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
