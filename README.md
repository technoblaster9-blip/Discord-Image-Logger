# 📸 Discord Image Request Logger

**Educational security research project.**

A small Python project demonstrating how image URLs generate HTTP requests when users open or load an image. This project is intended for **testing on systems you own or with explicit permission**.

## 🔎 How It Works

1. An image URL points to your test server.
2. A browser or Discord client requests that URL when the image is loaded.
3. Your server records basic request information for debugging and security research.
4. The request can be displayed in your local console for analysis.

> ⚠️ **Privacy notice:** Do not use this project to secretly identify, track, or profile other people. Only test with your own devices or users who have explicitly agreed to participate.

## ✨ Features

* 🐍 Written in Python
* 🌐 Simple HTTP request logging
* 📊 Useful for learning how web requests work
* 🔧 Easy to modify for security research
* 💻 Runs locally or on your own test server

## 🛠️ Requirements

* Python 3.10+
* A computer or server you control
* Basic knowledge of Python and HTTP

## 📥 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/THIS_REPO.git
cd THIS_REPO
```

Install the required dependencies:

```bash
Run setup.bat
```

## ▶️ Running

Start the application with:

```bash
python main.py
```

The server will display incoming test requests in the terminal.

## 🔐 Responsible Use

This project is provided for **educational and authorized security testing only**.

Do not use it to:

* Collect information from people without their knowledge
* Track or identify users
* Circumvent platform privacy protections
* Distribute disguised tracking links
* Store or share sensitive information

Use a local test environment or obtain explicit permission before testing with other users.

## 📚 Learning Goals

This project can help demonstrate:

* How HTTP requests work
* How browsers request external resources
* Basic web-server logging
* Client/server communication
* Privacy considerations when loading external content

## 📄 License

Use, modify, and learn from the project according to the license included in this repository.
