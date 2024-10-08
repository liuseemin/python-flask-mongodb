let groupCount = document.getElementById('dynamic-groups').children.length;
console.log(groupCount)

document.getElementById('add-group-btn').addEventListener('click', function() {
    let data = new FormData();
    data.append('group_id', groupCount);
    data.append('name', 'test')

    console.log(data.get('group_id'))

    fetch('/add_group', {
        'method': 'POST',
        'body': data
    })
    .then(response => response.json())
    .then(data => {
        // Append the new group HTML to the dynamic-groups div
        let dynamicGroupsDiv = document.getElementById('dynamic-groups');
        let tempDiv = document.createElement('div');
        tempDiv.innerHTML = data.new_group;
        dynamicGroupsDiv.appendChild(tempDiv.firstElementChild);

        // Increment the group count
        groupCount += 1;
    })
    .catch(error => {
        console.error('Error adding group:', error);
    });
});