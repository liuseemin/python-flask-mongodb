from flask import Flask, render_template, request, redirect, url_for, send_file
import matplotlib.pyplot as plt
import io
import base64

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
    ax.barh(y_pos, [end - start for start, end in zip(start_times, end_times)], left=start_times, color='skyblue')
    ax.set_yticks(y_pos)
    ax.set_yticklabels(task_names)
    ax.set_xlabel('Time')
    ax.set_title('Schedule')

    # Save the plot to an in-memory buffer
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()

    return buf

@app.route('/', methods=['GET', 'POST'])
def tpn(figdata=None):
    if request.method == 'POST':
        schedule_text = request.form['schedule']
        return redirect(url_for('schedule_image', schedule_text=schedule_text))
    
    figdata = base64.b64encode(generate_schedule('Task 1: 9-11\nTask 2: 12-14').getvalue()).decode('utf-8')
    return render_template('TPN-view.html', figdata=figdata)

@app.route('/schedule_image')
def schedule_image():
    schedule_text = request.args.get('schedule_text')
    buf = generate_schedule(schedule_text)
    figdata = base64.b64encode(buf.getvalue()).decode('utf-8')
    return redirect(url_for('tpn'), figdata=figdata)
    return redie
    # return send_file(buf, mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True)