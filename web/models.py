from extensions import db, bcrypt, login_manager
from flask_login import UserMixin
from datetime import datetime


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(32), unique=True, nullable=False)
    email         = db.Column(db.String(254), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class CoachAttempt(db.Model):
    __tablename__ = "coach_attempts"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    mode       = db.Column(db.String(10), nullable=False)
    key_hex    = db.Column(db.String(32), nullable=False)
    block_hex  = db.Column(db.String(32), nullable=False)
    correct    = db.Column(db.Integer, nullable=False)
    total      = db.Column(db.Integer, nullable=False)

    user = db.relationship("User", backref="coach_attempts")

    def __repr__(self):
        return f"<CoachAttempt {self.id} user={self.user_id} {self.correct}/{self.total}>"


class EncryptionAttempt(db.Model):
    __tablename__ = "encryption_attempts"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tool_name  = db.Column(db.String(50), nullable=False)
    mode       = db.Column(db.String(10), nullable=False)
    key_hex    = db.Column(db.String(64))
    input_hex  = db.Column(db.Text)
    output_hex = db.Column(db.Text)

    user = db.relationship("User", backref="encryption_attempts")

    def __repr__(self):
        return f"<EncryptionAttempt {self.id} tool={self.tool_name}>"
