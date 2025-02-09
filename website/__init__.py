from flask import Flask

# The create_app() function creates and returns a Flask app with the given configuration.
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjdjah kjshkjdhjs'
    # Creates a Flask app with a secret key (used for session management).

    from website.views import views
    from website.auth import auth # Imports the views and auth blueprints.

    app.register_blueprint(views, url_prefix='/') # Imports the views blueprints
    app.register_blueprint(auth, url_prefix='/') # Imports the auth blueprints
    # Registers blueprints (views and auth), which means different routes (pages) are handled separately.

    return app # Returns the app instance to main.py


# This is the entry point for the Flask application.
# If this script is run directly, it will start the Flask application.
