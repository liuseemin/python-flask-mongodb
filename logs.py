from flask import render_template, redirect, url_for, g, current_app
from flask_login import login_required
from db import get_db, mongo
from flask import Blueprint
from datetime import datetime

# database and collections
# db = get_db()
db = mongo.db
log_collection = db.logs
logs_bp = Blueprint('logs', __name__)

# log page
@logs_bp.route('/log')
@login_required
def log():
    logs = log_collection.find()
    return render_template('log.html', logs=logs)

# clear logs
@logs_bp.route('/clear_logs')
@login_required
def clear_logs():
    log_collection.delete_many({})
    return redirect(url_for('log'))

# Log method
def logger(category, action, user, target, message):
    log = {
        'category': category,
        'action': action,
        'user': user,
        'target': target,
        'message': message,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    log_collection.insert_one(log)