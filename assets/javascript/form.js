let otpIntervalId;
let clipboardTimer;
let otpDuration = 30; // Duration of OTP in seconds
let otpTimeLeft = otpDuration;

async function viewAccount(id) {
    const account = await fetchAccount(id);
    const modalBody = document.querySelector('#viewAccountModal .modal-body');
    const favorite = account.favorite ? 'checked' : '';
    let customFields = '';
    if (account.form_fields) {
        customFields += `<table class="table table-striped-columns table-sm">`;
        for (const [key, value] of Object.entries(account.form_fields)) {
            customFields += `
            <tr>
                <td><strong>${key}:</strong></td><td><span>${value || ''}</span></td>
            </tr>`;
        }
        customFields += `</table>`;
    }
    let otpData = '';
    if (account.otp) {
        otpData += `
        <tr>
            <td><strong>OTP Secret:</strong></td><td> <span id="viewOtp">${account.otp || ''}</span></td>
        </tr>
        <tr>
            <td><strong>Generated OTP:</strong></td><td> 
                <div class="row align-items-center">
                </div>
               
                <div class="col">
                    <div id="otp" class="alert alert-primary" role="alert" style="font-size: 1.5rem;">
                        <span id="viewGeneratedOtp">${account.generated_otp}</span>
                    </div>
                </div> 
                <!-- Progress Bar -->
                <div class="col">
                    <div class="progress">
                        <div id="otpTimer" class="progress-bar" role="progressbar" style="width: 100%;"></div>
                    </div>
                </div>
                &nbsp;
                <div class="col-auto">
                    <button class="btn btn-outline-dark" onclick="copyOtpToClipboard()">Copy</button>
                </div>
            </td>
        </tr>
        `;
    }

    let advisories = '';
    if (account.advisories) {
        advisories += `<ul>`;
        for (const [_key, value] of Object.entries(account.advisories)) {
            advisories += `<li>${value}</li>`;
        }
        advisories += `</ul>`;
    }
    const riskBackgroundColor = account.risk_bg_color;

    modalBody.innerHTML = `
        <table class="table table-striped-columns">
        <tr>
            <td><strong>ID:</strong></td><td><span id="viewLabel">${account.account_id || ''}</span></td>
        </tr>
        <tr>
            <td><strong>Label:</strong></td><td><span id="viewLabel">${account.label || ''}</span></td>
        </tr>
        <tr>
            <td><strong>Favorite:</strong></td><td><input type="checkbox" id="viewFavorite" ${favorite} disabled></td>
        </tr>
        <tr>
            <td><strong>Description:</strong></td><td><span id="viewDescription">${account.description || ''}.</span></td>
        </tr>
        <tr>
            <td><strong>Username:</strong></td><td> <span id="viewUsername">${account.username || ''}</span></td>
        </tr>
        <tr>
            <td><strong>Password:</strong> </td>
            <td class="d-flex">
                <input type="password" class="form-control" id="accountPassword" name="accountPassword" value="${account.password || ''}" disabled>
                &nbsp;
                <button id="viewPasswordButton" class="btn btn-outline-info" onclick="togglePasswordVisibility()">Show</button>
                &nbsp;
                <button class="btn btn-outline-dark" onclick="copyToClipboard('passwordValue')">Copy</button>
            </td>
        </tr>
        <tr>
            <td><strong>Email:</strong></td><td> <span id="viewEmail">${account.email || ''}</span></td>
        </tr>
        <tr>
            <td><strong>URL:</strong></td><td> <span id="viewUrl">${account.website_url || ''}</span></td>
        </tr>
        <tr>
            <td><strong>Category:</strong></td><td> <span id="viewCategory">${account.category || ''}</span></td>
        </tr>
        <tr>
            <td><strong>Tags:</strong></td><td> <span id="viewTags">${account.tags || ''}</span></td>
        </tr>
        ${otpData}
        <tr>
            <td><strong>Notes:</strong></td><td> <span id="viewNotes">${account.notes || ''}</span></td>
        </tr>
        <tr>
            <td><strong>Account Risk:</strong></td><td style="${riskBackgroundColor}"> <span id="viewNotes">${account.risk}</span></td>
        </tr>
        </table>
        <h5>Advisories:</h5>
        <div id="customFieldsView">
            ${advisories}
        </div>
        <!-- Custom Fields for View -->
        <h5>Custom Fields:</h5>
        <div id="customFieldsView">
            ${customFields}
        </div>
    `;
    // Show modal
    const viewModalElem = document.getElementById('viewAccountModal');
    const viewModal = new bootstrap.Modal(viewModalElem);

    if (document.getElementById('viewGeneratedOtp')) {
        viewModalElem.addEventListener('show.bs.modal', function (e) {
            startFetchingOTP();
        });

        // Event listener for when the modal is closed
        viewModalElem.addEventListener('hide.bs.modal', function (e) {
            stopFetchingOTP();
        });
    }
    await viewModal.show();
}

function  copyOtpToClipboard(){
    const otp = document.getElementById('viewGeneratedOtp').textContent;
    copyToClipboard(otp);
}

function resetProgressBar() {
    document.getElementById('otpTimer').style.width = '100%';
}

function updateProgressBar() {
    const percentage = (otpTimeLeft / otpDuration) * 100;
    document.getElementById('otpTimer').style.width = percentage + '%';
}

function fetchOTP() {
    const secret = document.getElementById('viewOtp').textContent;
    // Replace 'your_api_endpoint' with the actual API endpoint
    fetch('/ui/otp/generate?otp_secret=' + secret)
        .then(response => response.json())
        .then(data => {
            otpTimeLeft = otpDuration;
            resetProgressBar();
            if (data && data.otp_code) {
                document.getElementById('viewGeneratedOtp').textContent = data.otp_code;
            } else {
                console.error('didnt receive otp', data);
                stopFetchingOTP();
            }
        })
        .catch(error => {
            stopFetchingOTP();
            console.error('Error fetching OTP:', error)
        });
}

// Function to start fetching OTP
function startFetchingOTP() {
    stopFetchingOTP();
    if (otpIntervalId) clearInterval(otpIntervalId);
    otpIntervalId = setInterval(function() {
        if (new Date().getSeconds() % 30 == 0) {
            fetchOTP();
        } else if (otpTimeLeft > 0) {
            otpTimeLeft--;
            updateProgressBar();
        } else {
            fetchOTP();
        }
    }, 1000);
    fetchOTP();
}

// Function to stop fetching OTP
function stopFetchingOTP() {
    if (otpIntervalId) {
        clearInterval(otpIntervalId);
        otpIntervalId = null;
    }
}

async function editAccount(id) {
    document.getElementById('editAccountTitle').innerText = 'Edit Account';
    const account = await fetchAccount(id);
    await showAccountForm(account);
}

async function addAccount(vault_id) {
    document.getElementById('editAccountTitle').innerText = 'Add Account';
    const account = {
        account_id: '',
        vault_id: vault_id,
        version: 0,
        kind: 'Login',
        label: '',
        description: '',
        favorite: false,
        email: '',
        username: '',
        password: '',
        phone: '',
        website_url: '',
        category: '',
        tags: '',
        otp : '',
        notes: '',
        form_fields: {},
    };

    await showAccountForm(account);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        clearClipboardAfterDelay(text, 30000);  // 30 seconds delay
    }).catch(function(er) {
        console.error('Could not copy text: ', err);
    });
}

function clearClipboardAfterDelay(text, delay) {
    if (clipboardTimer) {
        clearTimeout(clipboardTimer);
    }
    clipboardTimer = setTimeout(function() {
        navigator.clipboard.readText().then(clipboardContent => {
            if (clipboardContent === text) {
                navigator.clipboard.writeText('');  // Clear the clipboard
            }
        }).catch(function(error) {
            console.error('Error reading clipboard:', error);
        });
    }, delay);
}


async function showAccountForm(account) {
    const favorite = account.favorite ? 'checked' : '';
    const modalBody = document.querySelector('#editAccountModal .modal-body');
    let category_opts = '';
    for (let i = 0; i < document.allCategories.length; i++) {
        const next = document.allCategories[i];
        const selected = account.category === next ? 'selected' : '';
        category_opts += `<option value="${next}" ${selected}>${next}</option>\n`;
    }
    modalBody.innerHTML = `
                    <div class="form-group mb-3">
                        <label>Name:</label>
                        <input type="hidden" name="account_id" value="${account.account_id}">
                        <input type="hidden" name="vault_id" value="${account.vault_id}">
                        <input type="hidden" name="version" name="version" value="${account.version}">
                        <input type="hidden" name="kind" name="kind" value="${account.kind}">
                        <input type="text" class="form-control" name="label" value="${account.label || ''}">
                    </div>
                    <div class="form-group mb-3 form-check">
                        <input type="checkbox" class="form-check-input" id="favorite" name="favorite">
                        <label class="form-check-label" for="favorite" ${favorite}>Favorite</label>
                    </div>
                    <div class="form-group mb-3">
                        <label for="description" class="form-label">Description:</label>
                        <input type="text" class="form-control" id="description" name="description" value="${account.description || ''}">
                    </div>
                    <div class="form-group mb-3">
                        <label for="username" class="form-label">Username:</label>
                        <input type="text" class="form-control" id="username" name="username" value="${account.username || ''}">
                    </div>
                    <div class="form-group mb-3">
                        <label for="password" class="form-label">Password:</label>
                        <input type="password" class="form-control" id="password" name="password" value="${account.password || ''}">
                    </div>
                    <div class="form-group mb-3">
                        <label>Email:</label>
                        <input type="email" class="form-control" name="email" value="${account.email || ''}">
                    </div>
                    <div class="form-group mb-3">
                        <label>Phone:</label>
                        <input type="tel" class="form-control" name="phone" value="${account.phone || ''}">
                    </div>
                    <div class="form-group mb-3">
                        <label for="website_url" class="form-label">Website URL:</label>
                        <input type="url" class="form-control" id="website_url" name="website_url" value="${account.url || ''}">
                    </div>
                    <div class="form-group mb-3">
                        <label for="editCategory" class="form-label">Category: </label>
                        <select class="form-select" id="editCategory" name="category">
                          ${category_opts}
                        </select>
                    </div>
                    <div class="form-group mb-3">
                        <label>Tags (separated by commas):</label>
                        <input type="text" class="form-control" name="tags" value="${account.tags || ''}" placeholder="Add tags...">
                    </div>
                    <div class="form-group mb-3">
                        <label>OTP Secret (Base32):</label>
                        <input type="text" class="form-control" name="otp" value="${account.otp || ''}" placeholder="Base32 TOTP secret">
                    </div>
                    <div class="form-group mb-3">
                        <label for="notes" class="form-label">Notes:</label>
                        <textarea class="form-control" id="notes" name="notes">${account.notes}</textarea>
                    </div>

                    <!-- Custom Fields for Edit -->
                    <h5>Custom Fields:</h5>
                    <div class="form-group mb-3" id="customFieldsEdit">
                    </div>

                    <button class="btn btn-info mb-3" type="button" onclick="addCustomField()">+ Add Custom Field</button>
    `;

    const customFieldsContainer = document.getElementById('customFieldsEdit');
    if (account.form_fields) {
        for (const [key, value] of Object.entries(account.form_fields)) {
            const rowDiv = buildCustomField(key, value);
            customFieldsContainer.appendChild(rowDiv);
        }
    }
    const editModal = new bootstrap.Modal(document.getElementById('editAccountModal'));
    await editModal.show();
}

function buildCustomField(name, value) {
    const customFieldsContainer = document.getElementById('customFieldsEdit');
    // Create row div
    const rowDiv = document.createElement('div');
    rowDiv.className = 'row mb-3';

    // Field Name Input
    const fieldNameDiv = document.createElement('div');
    fieldNameDiv.className = 'col';
    const fieldNameInput = document.createElement('input');
    fieldNameInput.type = 'text';
    fieldNameInput.name = 'custom_name';
    fieldNameInput.value = name;
    fieldNameInput.className = 'form-control';
    fieldNameInput.placeholder = 'Field Name';
    fieldNameDiv.appendChild(fieldNameInput);

    // Field Value Input
    const fieldValueDiv = document.createElement('div');
    fieldValueDiv.className = 'col';
    const fieldValueInput = document.createElement('input');
    fieldValueInput.type = 'text';
    fieldValueInput.name = 'custom_value';
    fieldValueInput.value = value;
    fieldValueInput.className = 'form-control';
    fieldValueInput.placeholder = 'Field Value';
    fieldValueDiv.appendChild(fieldValueInput);

    // Remove Button
    const removeButtonDiv = document.createElement('div');
    removeButtonDiv.className = 'col-auto';
    const removeButton = document.createElement('button');
    removeButton.className = 'btn btn-danger btn-sm';
    removeButton.innerText = 'Remove';
    removeButton.type = 'Button';
    removeButton.onclick = function () {
        customFieldsContainer.removeChild(rowDiv);
    }
    removeButtonDiv.appendChild(removeButton);

    // Append all to row
    rowDiv.appendChild(fieldNameDiv);
    rowDiv.appendChild(fieldValueDiv);
    rowDiv.appendChild(removeButtonDiv);

    return rowDiv;
}


function addCustomField(name = '', value = '') {
    const customFieldsContainer = document.getElementById('customFieldsEdit');
    const rowDiv = buildCustomField(name, value);
    // Append row to custom fields container
    customFieldsContainer.appendChild(rowDiv);
}


async function shareVault() {
    // Show modal
    const viewModal = new bootstrap.Modal(document.getElementById('shareVaultModal'));
    await viewModal.show();
}

async function handleShareVault(vaultId) {
    const username = document.getElementById('shareVaultUserInput').value;
    const response = await fetch(`/ui/vaults/${vaultId}/share?target_username=${username}`, {
        method: 'POST',
    });
    if (!response.ok) {
        alert(`Could not share vault: ${response.status} ${response.statusText}`);
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
    }
    const viewModal = bootstrap.Modal.getInstance(document.getElementById('shareVaultModal'));
    await viewModal.hide();
    showToast(`Shared vault with the ${username}!`);
    return true; //await response.json();
}

async function handleShareAccount(vaultId) {
    const shareAccountId = document.getElementById('shareAccountId').value;
    const username = document.getElementById('shareAccountUserInput').value;
    const response = await fetch(`/ui/vaults/${vaultId}/accounts/${shareAccountId}/share?target_username=${username}`, {
        method: 'POST',
    });
    if (!response.ok) {
        alert(`Could not share account: ${response.status} ${response.statusText}`);
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
    }
    const viewModal = bootstrap.Modal.getInstance(document.getElementById('shareAccountModal'));
    await viewModal.hide();
    showToast(`Shared account with the ${username}!`);
    return true; //await response.json();
}

async function shareAccount(id) {
    const shareAccountId = document.getElementById('shareAccountId');
    shareAccountId.value = id;
    // Show modal
    const viewModal = new bootstrap.Modal(document.getElementById('shareAccountModal'));
    await viewModal.show();
}

async function accountRisk(id) {

}

async function importAccounts() {
    // Show modal
    const viewModal = new bootstrap.Modal(document.getElementById('importAccountsModal'));
    await viewModal.show();
}

async function exportAccounts() {
    // Show modal
    const viewModal = new bootstrap.Modal(document.getElementById('exportAccountsModal'));
    await viewModal.show();
}

async function hideExportAccounts() {
    // Show modal
    const viewModal = new bootstrap.Modal(document.getElementById('exportAccountsModal'));
    await viewModal.hide();
}

async function handleImportAccounts(vaultId) {
    const password = document.getElementById("importPasswordInput").value;
    let progressBar = document.querySelector('.progress-bar');
    let fileInput = document.getElementById('fileImport');

    if (fileInput.files.length === 0) {
        alert("Please select a file to upload CSV");
        return;
    }

    let formData = new FormData();
    formData.append('file', fileInput.files[0]);
    const path = password ? `/ui/vaults/${vaultId}/accounts/import?password=${password}` : `/ui/vaults/${vaultId}/accounts/import`;

    try {
        const response = await fetch(path, {
            method: 'POST',
            body: formData
        });
        if (!response.ok) {
            if (password) {
                alert(`Could not import accounts, please verify password: ${response.status} ${response.statusText}`);
            } else {
                alert(`Could not import accounts, please try again: ${response.status} ${response.statusText}`);
            }
            throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
        }

        let reader = response.body.getReader();
        let decoder = new TextDecoder();
        await reader.read().then(function processText({done, value}) {
            if (done) return;
            let lastEvent = decoder.decode(value).trim();
            if (lastEvent.includes(':')) {
                let parsedData = lastEvent.split(":")[1].trim();
                progressBar.style.width = parsedData + '%';
                progressBar.textContent = parsedData + '%';
            }
            return reader.read().then(processText);
        });
        const viewModal = new bootstrap.Modal(document.getElementById('importAccountsModal'));
        await viewModal.hide();
        showToast('Imported accounts', () => {
            location.reload();
        })
    } catch (error) {
        console.error('Error:', error);
        alert('Error uploading file: ' + error);
    }
}

async function handleExportAccounts(vaultId) {
    const password = document.getElementById("exportPasswordInput").value;
    const progressBar = document.getElementById("exportProgress");
    progressBar.style.width = '0%';

    // Start SSE to get progress updates
    // const evtSource = new EventSource(`/ui/vaults/{vault_id}/accounts/export?password=${password}`);
    // evtSource.onmessage = function (event) {
    //     const percentage = event.data;
    //     progressBar.style.width = percentage + '%';
    //     console.info(percentage);
    //     if (percentage === "100") {
    //         evtSource.close();
    //     }
    // };
    const a = document.createElement('a');
    a.href = password ? `/ui/vaults/${vaultId}/accounts/export?password=${password}` : `/ui/vaults/${vaultId}/accounts/export`;
    a.download = password ? 'exported_accounts.encrypted_csv' : 'exported_accounts.csv';
    a.click();
    const viewModal = bootstrap.Modal.getInstance(document.getElementById('exportAccountsModal'));
    await viewModal.hide();
}


async function deleteAccount(id) {
    if (confirm('Are you sure you want to delete this account?')) {
        try {
            const response = await fetch(`/ui/accounts/${id}/delete`, {
                    method: 'DELETE'
                }
            );
            if (!response.ok) {
                alert(`Could not delete account ${response.status} ${response.statusText}`);
                throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
            }
            showToast('Data deleted successfully!', () => {
                location.reload();
            });
        } catch (e) {
            console.error('Failed to delete data', e);
        }
    }
}

async function handleSaveAccount(form) {
    const title = document.getElementById('editAccountTitle').innerText.toLowerCase();
    const path = title.includes('add') ? '/ui/accounts/create' : '/ui/accounts/update';
    form = form || document.forms['accountEditForm']; //document.getElementById('accountEditForm');
    const formData = new FormData(form);
    try {
        await postData(path, formData);
        showToast('Saved account successfully', () => {
            location.reload();
        })
    } catch (e) {
        console.error('Failed to update the account', e);
    }
}

function togglePasswordVisibility() {
    const passwordButtonSpan = document.getElementById('viewPasswordButton');
    const accountPassword = document.getElementById('accountPassword');
    if (accountPassword.type === 'password') {
        accountPassword.type = 'text';
        passwordButtonSpan.innerText = "Hide";
    } else {
        accountPassword.type = 'password';
        passwordButtonSpan.innerText = "Show";
    }
}

async function fetchAccount(id) {
    const response = await fetch(`/ui/accounts/${id}`, {
        method: 'GET',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });
    if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
    }
    try {
        return await response.json();
    } catch (e) {
        location.reload();
    }
}

async function postData(path, data) {
    const response = await fetch(path, {
        method: 'POST',
        body: data,
    });
    if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
    }
    return true; //await response.json();
}

async function initEventHandlers() {
    await initEventHandler(document.getElementById('shareVaultUserInput'));
    await initEventHandler(document.getElementById('shareAccountUserInput'));
}

async function autocompleteUsername(term) {
    if (term.length < 2) {
        return [];
    }
    const response = await fetch(`/ui/users/autocomplete?term=${term}`);
    return await response.json();
}

async function initEventHandler(inp) {
    let currentFocus;
    inp.addEventListener("input", async function (e) {
        const val = this.value;
        /* Close any already open lists of autocompleted values */
        closeAllLists();
        if (!val) {
            return false;
        }
        currentFocus = -1;
        const usernames = await autocompleteUsername(val);
        const a = document.createElement("DIV");
        a.setAttribute("id", inp.id + "autocomplete-list");
        a.setAttribute("class", "autocomplete-items");
        inp.parentNode.appendChild(a);

        for (let i = 0; i < usernames.length; i++) {
            if (usernames[i].substr(0, val.length).toUpperCase() === val.toUpperCase()) {
                const b = document.createElement("DIV");
                b.innerHTML = "<strong>" + usernames[i].substr(0, val.length) + "</strong>";
                b.innerHTML += usernames[i].substr(val.length);
                b.innerHTML += "<input type='hidden' value='" + usernames[i] + "'>";
                b.addEventListener("click", function (e) {
                    inp.value = this.getElementsByTagName("input")[0].value;
                    closeAllLists();
                });
                a.appendChild(b);
            }
        }
    });

    /* Execute a function presses a key on the keyboard: */
    inp.addEventListener("keydown", function (e) {
        var x = document.getElementById(this.id + "autocomplete-list");
        if (x) x = x.getElementsByTagName("div");
        if (e.keyCode == 40) {
            /* If the arrow DOWN key is pressed,
            increase the currentFocus variable: */
            currentFocus++;
            /* And and make the current item more visible: */
            addActive(x);
        } else if (e.keyCode == 38) { //up
            /* If the arrow UP key is pressed,
            decrease the currentFocus variable: */
            currentFocus--;
            /* And and make the current item more visible: */
            addActive(x);
        } else if (e.keyCode == 13) {
            /* If the ENTER key is pressed, prevent the form from being submitted, */
            e.preventDefault();
            if (currentFocus > -1) {
                /* And simulate a click on the "active" item: */
                if (x) x[currentFocus].click();
            }
        }
    });

    function addActive(x) {
        /* A function to classify an item as "active": */
        if (!x) return false;
        /* Start by removing the "active" class on all items: */
        removeActive(x);
        if (currentFocus >= x.length) currentFocus = 0;
        if (currentFocus < 0) currentFocus = (x.length - 1);
        /* Add class "autocomplete-active": */
        x[currentFocus].classList.add("autocomplete-active");
    }

    function removeActive(x) {
        /* A function to remove the "active" class from all autocomplete items: */
        for (var i = 0; i < x.length; i++) {
            x[i].classList.remove("autocomplete-active");
        }
    }

    function closeAllLists(elmnt) {
        /* Close all autocomplete lists in the document,
        except the one passed as an argument: */
        var x = document.getElementsByClassName("autocomplete-items");
        for (var i = 0; i < x.length; i++) {
            if (elmnt != x[i] && elmnt != inp) {
                x[i].parentNode.removeChild(x[i]);
            }
        }
    }

    /* Execute a function when someone clicks in the document: */
    document.addEventListener("click", function (e) {
        closeAllLists(e.target);
    });
}

function buildGauge(riskGaugeCtx, data, score, chartType) {
    return new Chart(riskGaugeCtx, {
        type: chartType || 'doughnut',
        data: {
            labels: ['Compromised', 'Weak', 'Moderate', 'Strong', 'Healthy'],
            datasets: [{
                data: data,
                backgroundColor: [
                    'rgb(255, 99, 132)',
                    'rgb(255, 159, 64)',
                    'rgb(255, 205, 86)',
                    'rgb(75, 192, 192)',
                    'rgb(54, 162, 235)',
                ],
                hoverOffset: 4
            }]
        },
        options: {
            rotation: 270, // Start the gauge from the bottom
            circumference: 180, // Create a half-circle gauge
            cutout: '80%', // Increase this for a thinner ring (more like a gauge)
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                animateScale: true,
                animateRotate: true
            },
            plugins: {
                legend: {
                    position: 'top',
                    //display: false
                },
                datalabels: {
                    display: true,
                    backgroundColor: '#ccc',
                    borderRadius: 3,
                    font: {
                        color: 'red',
                        weight: 'bold',
                    },
                },
                afterDraw: chart => {
                    const width = chart.width,
                        height = chart.height,
                        ctx = chart.ctx;

                    ctx.restore();
                    const fontSize = (height / 114).toFixed(2);
                    ctx.font = fontSize + "em sans-serif";
                    ctx.textBaseline = "middle";

                    const text = score,
                        textX = Math.round((width - ctx.measureText(text).width) / 2),
                        textY = height / 2;

                    ctx.fillText(text, textX, textY);
                    ctx.save();
                },
            }
        },
    });
}

async function scheduleAnalysis() {
    const response = await fetch(`/ui/password/schedule_password_analysis`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
    })
    if (response.ok) {
        showToast('Scheduled password analysis!');
    } else {
        alert(`Could not schedule password analysis: ${response.status} ${response.statusText}`);
    }
}

async function generatePassword() {
    const form = document.getElementById('passwordForm');
    const formData = new FormData(form);
    const queryParams = new URLSearchParams(formData).toString();

    const response = await fetch(`/ui/password/generate?${queryParams}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
    })
    const data = await response.json();
    const password = data.password;

    const passwordDisplaySection = document.getElementById('passwordDisplaySection');
    const generatedPasswordInput = document.getElementById('generatedPassword');

    generatedPasswordInput.value = password;
    passwordDisplaySection.style.display = 'block';
    passwordDisplaySection.scrollIntoView({behavior: 'smooth', block: 'center'});
}

function copyPassword() {
    const passwordInput = document.getElementById('generatedPassword');
    passwordInput.select();
    passwordInput.setSelectionRange(0, 99999); // For mobile devices
    document.execCommand('copy');

    showToast('Password copied to clipboard!');
}


// Function to open the modal to edit a category
function editCategory(name) {
    document.getElementById('categoryName').value = name;
    document.getElementById('categoryModalLabel').value = 'Edit Category';
    var categoryModal = new bootstrap.Modal(document.getElementById('categoryModal'));
    categoryModal.show();
}

// Function to prepare the modal to add a new category
function prepareNewCategoryModal() {
    document.getElementById('categoryName').value = '';
    document.getElementById('categoryModalLabel').value = 'Add New Category';
}

// Function to save the category
async function saveCategory() {
    const name = document.getElementById('categoryName').value;

    const response = await fetch(`/ui/categories/${name}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
    })
    if (!response.ok) {
        alert(`Could not add category ${response.status} ${response.statusText}`);
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
    }
    const viewModal = bootstrap.Modal.getInstance(document.getElementById('categoryModal'));
    await viewModal.hide();
    showToast('Saved category', () => {
        location.reload();
    });
}

// Function to delete the category
async function deleteCategory(name) {
    if (confirm(`Are you sure you want to delete this category '${name}'?`)) {
        try {
            const response = await fetch(`/ui/categories/${name}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            if (!response.ok) {
                alert(`Could not delete category ${response.status} ${response.statusText}`);
                throw new Error(`HTTP error! Status: ${response.status} ${response.statusText}`);
            }
            showToast('Category deleted successfully!', () => {
                location.reload();
            });
        } catch (e) {
            console.error('Failed to delete data', e);
        }
    }
}


function showToast(message, callback) {
    const modalEl = document.getElementById('messageModal');
    const modalBody = modalEl.querySelector('.modal-body');
    modalBody.textContent = message; // Set the message text

    const modal = new bootstrap.Modal(modalEl);
    modal.show();

    // Automatically hide the modal after a second
    setTimeout(() => {
        modal.hide();
        if (callback) {
            callback();
        }
    }, 1000);
}
