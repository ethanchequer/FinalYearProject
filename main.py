# imports the create_app() function from website/__init__.py.
from website import create_app

app = create_app()

# Runs the app when the script is executed.
if __name__ == "__main__":
    app.run(debug=True)
    # app.run(host="0.0.0.0", port=8000)  # Run on external IP and port
    # app.run(port=8000)  # Run on localhost on port 8000
    # app.run(host="127.0.0.1", port=8000)  # Run on localhost on port 8000
