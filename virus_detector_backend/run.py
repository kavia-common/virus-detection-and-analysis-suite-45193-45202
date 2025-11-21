from app import app

if __name__ == "__main__":
    # Bind to host and preview port while keeping debug off by default
    app.run(host="0.0.0.0", port=3001)
