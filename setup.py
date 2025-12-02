from app import app, create_db_and_users

# Run the database setup function within the Flask application context
with app.app_context():
    create_db_and_users()
    print("--- Database and initial users created successfully ---")