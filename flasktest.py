from app import db
from app.models import User, Post
from app import app


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Post': Post}


if __name__ == '__main__':
    app.run(debug=True, port=8080, host="localhost")
