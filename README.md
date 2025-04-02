```md
# Tiny Second-hand Shopping Platform 

A simple secondhand trading web application with user registration, product posting, reporting system, and admin management panel.

> ⚠️ This project is intended to run on Linux-based systems (Ubuntu, WSL, etc).

## 🛠 Setup

Requires Python 3.9+ and [Miniconda](https://docs.anaconda.com/free/miniconda/index.html) or Anaconda.

```bash
conda env create -f enviroments.yaml
conda activate secure_coding
```

## 🚀 Run the Server

```bash
python app.py
```

## 🌐 External Access (optional)

You can expose the local server using ngrok:

```bash
sudo snap install ngrok  # install (if needed)
ngrok http 5000
```

## 🗂 Database Initialization (only once)

```python
# In Python shell
from app import init_db
init_db()
```

---

> The app uses SQLite (`market.db`) as the database.  
> To enable admin features, manually set a user's role to `'admin'` in the `user` table.
```

