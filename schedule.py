from flask import Flask, render_template, request, redirect, url_for, send_file
import matplotlib.pyplot as plt
import io
import base64
import numpy as np

app = Flask(__name__)

# Function to parse user input and create a schedule graph in-memory
def generate_schedule(schedule_text):
    tasks = schedule_text.split('\n')
    task_names = []
    start_times = []
    end_times = []

    for task in tasks:
        try:
            task_name, time_range = task.split(':')
            start_time, end_time = time_range.split('-')
            task_names.append(task_name.strip())
            start_times.append(int(start_time.strip()))
            end_times.append(int(end_time.strip()))
        except ValueError:
            continue

    # Create a simple bar plot for the schedule
    fig, ax = plt.subplots(figsize=(8, 6))
    y_pos = range(len(task_names))
    p = ax.barh(y_pos, [end - start for start, end in zip(start_times, end_times)], left=start_times, color='skyblue')
    ax.set_yticks(y_pos)
    ax.set_yticklabels(task_names)
    ax.set_xticks(np.arange(0, 24, 1))
    ax.set_xlabel('Time')
    ax.set_title('Schedule')
    ax.bar_label(p, labels=task_names, label_type='center')

    # Save the plot to an in-memory buffer
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()

    return buf

@app.route('/', methods=['GET', 'POST'])
def tpn():
    if request.method == 'POST':
        schedule_text = request.form['schedule']
        buf = generate_schedule(schedule_text)
        return send_file(buf, mimetype='image/png')
    return render_template('TPN-view.html')

if __name__ == '__main__':
    app.run(debug=True)