let otpIntervalId;
let clipboardTimer;
let otpDuration = 30; // Duration of OTP in seconds
let otpTimeLeft = otpDuration;
let idleTimer;
let sessionCheckInterval;
const IDLE_TIME_LIMIT = 300000; // 5 minutes in milliseconds


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
    let otpData = buildOtpSection(account.otp, account.generated_otp);

    let advisories = '';
    if (account.advisories) {
        advisories += `<ul>`;
        for (const [_key, value] of Object.entries(account.advisories)) {
            advisories += `<li>${value}</li>`;
        }
        advisories += `</ul>`;
    }
    const riskImage = account.risk_image ? `<img width="32" height="32" src="${account.risk_image}">` : '';

    let expiration = buildExpiration(account.expired, account.expires_at_short);
    let due = buildExpiration(account.overdue, account.due_at_short);
    modalBody.innerHTML = `
        <table class="table table-striped-columns">
            <tr>
                <td><strong>ID:</strong></td>
                <td><span id="viewLabel">${account.account_id || ''}</span></td>
            </tr>
            <tr>
                <td><strong>Label:</strong></td>
                <td><span id="viewLabel">${account.label || ''}</span></td>
            </tr>
            <tr>
                <td>
                    <strong>Favorite:</strong><br>
                    <input type="checkbox" id="viewFavorite" ${favorite} disabled>
                </td>
                <td>
                    <strong>Category:</strong><br>
                    <span id="viewCategory">${account.category || ''}</span>
                </td>
            </tr>
            <tr>
                <td><strong>Tags:</strong></td>
                <td><span id="viewTags">${account.tags || ''}</span></td>
            </tr>
        </table>
        
        <div class="accordion" id="accountDetailsAccordion theme-container">
            <!-- Login Information Section -->
            <div class="accordion-item theme-container">
                <h2 class="accordion-header theme-container" id="headingLoginInfo">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseLoginInfo" aria-expanded="false" aria-controls="collapseLoginInfo">
                        Login Details
                    </button>
                </h2>
                <div id="collapseLoginInfo" class="accordion-collapse collapse" aria-labelledby="headingLoginInfo" data-bs-parent="#accountDetailsAccordion">
                    <div class="accordion-body">
                        <table class="table table-striped-columns">
                            <tr>
                                <td><strong>Username:</strong></td><td> <span id="viewUsername">${account.username || ''}</span></td>
                            </tr>
                            <tr>
                                <td><strong>Password:</strong> </td>
                                <td class="d-flex">
                                    <input type="password" class="form-control" id="accountPassword" name="accountPassword" value="" disabled>
                                    &nbsp;
                                    <button id="viewPasswordButton" class="btn btn-outline-info" onclick="togglePasswordVisibility()">Show</button>
                                    &nbsp;
                                    <button id="copyPasswordButton" class="btn btn-outline-warning">Copy</button>
                                </td>
                            </tr>
                            <tr>
                                <td><strong>Expires At:</strong></td><td>${expiration}</td>
                            </tr>
                            <tr>
                                <td><strong>URL:</strong></td><td> <span id="viewUrl">${account.website_url || ''}</span></td>
                            </tr>
                        </table>
                        ${otpData}
                    </div>
                </div>
            </div>

            <!-- Contact Information Section -->
            <div class="accordion-item theme-container">
                <h2 class="accordion-header theme-container" id="headingContactInfo">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseContactInfo" aria-expanded="false" aria-controls="collapseContactInfo">
                        Contact Details
                    </button>
                </h2>
                <div id="collapseContactInfo" class="accordion-collapse collapse" aria-labelledby="headingContactInfo" data-bs-parent="#accountDetailsAccordion">
                    <div class="accordion-body">
                        <table class="table table-striped-columns">
                            <tr>
                                <td><strong>Description:</strong></td><td><span id="viewDescription">${account.description || ''}.</span></td>
                            </tr>
                            <tr>
                                <td><strong>Email:</strong></td><td> <span id="viewEmail">${account.email || ''}</span></td>
                            </tr>
                            <tr>
                                <td><strong>Phone:</strong></td><td> <span id="viewPhone">${account.phone || ''}</span></td>
                            </tr>
                            <tr>
                                <td><strong>Address:</strong></td><td> <span id="viewAddress">${account.address || ''}</span></td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>

            <div class="accordion-item theme-container">
                <h2 class="accordion-header theme-container" id="headingNotesInfo">
                    <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseNotesInfo" aria-expanded="false" aria-controls="collapseNotesInfo">
                        Notes & Custom Fields
                    </button>
                </h2>
                <div id="collapseNotesInfo" class="accordion-collapse collapse" aria-labelledby="headingNotesInfo" data-bs-parent="#accountDetailsAccordion">
                    <div class="accordion-body">
                        <table class="table table-striped-columns">
                            <tr>
                                <td><strong>Due At:</strong></td><td>${due}</td>
                            </tr>
                            <tr>
                                <td><strong>Notes:</strong></td><td> <span id="viewNotes">${account.notes || ''}</span></td>
                            </tr>
                        </table>
                        <h5>Custom Fields:</h5>
                        <div id="customFieldsView">
                            ${customFields}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <table class="table table-striped-columns">
            <tr>
                <td><strong>Account Risk:</strong></td><td>${riskImage}&nbsp;<span id="viewNotes">${account.risk}</span></td>
            </tr>
        </table>
        <div id="advisoryFieldsView">
            ${advisories}
        </div>
        <table class="table table-striped-columns">
            <tr>
                <td><strong>Created At:</strong></td><td><span id="viewCreated">${account.created_at}</span></td>
            </tr>
            <tr>
                <td><strong>Updated At:</strong></td><td><span id="viewCreated">${account.updated_at}</span></td>
            </tr>
        </table>
        `;
    document.getElementById('accountPassword').value = account.password || '';
    document.getElementById('copyPasswordButton').onclick = function () {
        copyToClipboard(account.password);
    };
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
    if (account.kind === 'Contacts' || account.category === 'Contacts') {
        expandAccordionSection('collapseContactInfo');
    } else if (account.kind === 'Notes' || account.kind === 'Custom' || account.category === 'Notes' || account.category === 'Custom') {
        expandAccordionSection('collapseNotesInfo');
    } else if (account.kind === 'Logins' || account.category === 'Logins') {
        expandAccordionSection('collapseLoginInfo');
    }
    await viewModal.show();
}

function buildExpiration(expired, expires_at) {
    if (expired) {
        return `<div class="alert alert-danger d-flex align-items-center" role="alert">
  <svg class="bi flex-shrink-0 me-2" width="24" height="24" role="img" aria-label="Danger:"><use xlink:href="#exclamation-triangle-fill"/></svg>
  <div>
    ${expires_at}
  </div>
</div>`;
    } else if (expires_at) {
        return `<div class="alert alert-primary d-flex align-items-center" role="alert">
  <svg class="bi flex-shrink-0 me-2" width="24" height="24" role="img" aria-label="Info:"><use xlink:href="#info-fill"/></svg>
  <div>
    ${expires_at}
  </div>
</div>`;
    } else {
        return '';
    }
}

function buildOtpSection(otp, generatedOtp) {
    if (!otp) {
        return '';
    }
    return `
<table class="table table-striped-columns">
    <tr>
        <td><strong>OTP Secret:</strong></td>
        <td> 
            <span id="viewOtp">${otp || ''}</span>
        </td>
    </tr>
    <tr>
        <td><strong>Generated OTP:</strong></td>
        <td>
            <!-- OTP Display and Copy Button Row -->
            <div class="d-flex justify-content-between align-items-center">
                <div id="otp" class="alert alert-primary" role="alert" style="font-size: 1.5rem;">
                    <span id="viewGeneratedOtp">${generatedOtp}</span>
                </div>
                <button class="btn btn-outline-warning" onclick="copyOtpToClipboard()">Copy</button>
            </div>

            <!-- Progress Bar -->
            <div class="progress mt-2">
                <div id="otpTimer" class="progress-bar" role="progressbar" style="width: 100%;"></div>
            </div>
        </td>
    </tr>
</table>
        `;
}

function copyOtpToClipboard() {
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
    doFetch('/ui/otp/generate?otp_secret=' + secret)
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

function handleFetchingOTP() {
    if (document.hidden) {
        stopFetchingOTP();
    } else {
        startFetchingOTP();
    }
}

// Function to start fetching OTP
function startFetchingOTP() {
    stopFetchingOTP();
    if (otpIntervalId) clearInterval(otpIntervalId);
    otpIntervalId = setInterval(function () {
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

async function editAccount(id, kind) {
    document.getElementById('editAccountTitle').innerText = `Edit ${getAccountDisplayKind(kind)}`;
    const account = await fetchAccount(id);
    await showAccountForm(account);
}

function getAccountDisplayKind(kind) {
    if (kind === 'Notes') {
        return 'Note';
    } else if (kind === 'Contacts') {
        return 'Contact';
    }
    return 'Account';
}

async function addAccount(vault_id, kind) {
    document.getElementById('editAccountTitle').innerText = `Add ${getAccountDisplayKind(kind)}`;
    const account = {
        account_id: '',
        vault_id: vault_id,
        version: 0,
        kind: kind || 'Logins',
        label: '',
        description: '',
        favorite: false,
        email: '',
        username: '',
        password: '',
        phone: '',
        address: '',
        website_url: '',
        category: '',
        tags: '',
        otp: '',
        notes: '',
        form_fields: {},
    };

    await showAccountForm(account);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function () {
        clearClipboardAfterDelay(text, 30000);  // 30 seconds delay
    }).catch(function (er) {
        console.error('Could not copy text: ', err);
    });
}

function clearClipboardAfterDelay(text, delay) {
    if (clipboardTimer) {
        clearTimeout(clipboardTimer);
    }
    // readText not supported on firefox
    if (navigator.clipboard.readText) {
        clipboardTimer = setTimeout(function () {
            navigator.clipboard.readText().then(clipboardContent => {
                if (clipboardContent === text) {
                    navigator.clipboard.writeText('');  // Clear the clipboard
                }
            }).catch(function (error) {
                console.error('Error reading clipboard:', error);
            });
        }, delay);
    }
}

async function showAccountForm(account) {
    const favorite = account.favorite ? 'checked' : '';
    const modalBody = document.querySelector('#editAccountModal .modal-body');
    let category_opts = '';
    for (let i = 0; i < document.allCategories.length; i++) {
        const next = document.allCategories[i];
        const selected = account.category ? (account.category === next ? 'selected' : '') :
            (account.kind === next ? 'selected' : '');
        category_opts += `<option value="${next}" ${selected}>${next}</option>\n`;
    }
    modalBody.innerHTML = `
                    <div class="form-group mb-3">
                        <input type="hidden" name="account_id" value="${account.account_id}">
                        <input type="hidden" name="vault_id" value="${account.vault_id}">
                        <input type="hidden" name="version" name="version" value="${account.version}">
                        <input type="hidden" id="accountKind" name="kind" value="${account.kind}">
                        <label>Label:</label>
                        <input type="text" class="form-control" name="label" value="${account.label || ''}">
                    </div>
                    <div class="row mb-3">
                        <!-- Favorite Checkbox -->
                        <div class="col-md-6 d-flex align-items-center">
                            <div class="form-check">
                                <input type="checkbox" class="form-check-input" id="favorite" name="favorite" ${favorite}>
                                <label class="form-check-label" for="favorite">Favorite</label>
                            </div>
                        </div>

                        <!-- Category Dropdown -->
                        <div class="col-md-6">
                            <label for="editCategory" class="form-label">Category: </label>
                            <select class="form-select" id="editCategory" name="category">
                                ${category_opts}
                            </select>
                        </div>
                    </div>
                    <div class="form-group mb-3">
                        <label>Tags (separated by commas):</label>
                        <input type="text" class="form-control" name="tags" value="${account.tags || ''}" placeholder="Add tags...">
                    </div>
                                    
                    <!-- Collapsible Group for Login Details -->
                    <div class="accordion theme-container" id="accordionAccount">
                        <div class="accordion-item theme-container">
                            <h2 class="accordion-header theme-container" id="headingLogin">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseLogin" aria-expanded="false" aria-controls="collapseLogin">
                                    Login Details
                                </button>
                            </h2>
                            <div id="collapseLogin" class="accordion-collapse collapse" aria-labelledby="headingLogin" data-bs-parent="#accordionAccount">
                                <div class="accordion-body">
                                    <div class="form-group mb-3">
                                        <label for="username" class="form-label">Username:</label>
                                        <input type="text" class="form-control" id="username" name="username" value="${account.username || ''}">
                                    </div>
                                    <div class="form-group mb-3">
                                        <label for="password" class="form-label">Password:</label>
                                        <input type="password" class="form-control" id="password" name="password">
                                    </div>
                                    <div class="form-group mb-3">
                                        <label for="website_url" class="form-label">Website URL:</label>
                                        <input type="url" class="form-control" id="website_url" name="website_url" value="${account.website_url || ''}">
                                    </div>
                                    <div class="mb-3">
                                        <label for="expiresAt" class="form-label">Expires At:</label>
                                        <input type="date" class="form-control" id="expiresAt" name="expires_at" value="${account.expires_at_short || ''}" pattern="\\d{4}-\\d{2}-\\d{2}">
                                        <div class="form-text">Please select password expiration date.</div>
                                    </div>
                                    <div class="form-group mb-3">
                                        <label>OTP Secret (Base32):</label>
                                        <input type="text" class="form-control" name="otp" value="${account.otp || ''}" placeholder="Base32 TOTP secret">
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Collapsible Group for Contact Details -->
                        <div class="accordion-item theme-container">
                            <h2 class="accordion-header theme-container" id="headingContact">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseContact" aria-expanded="false" aria-controls="collapseContact">
                                    Contact Details
                                </button>
                            </h2>
                            <div id="collapseContact" class="accordion-collapse collapse" aria-labelledby="headingContact" data-bs-parent="#accordionAccount">
                                <div class="accordion-body">
                                    <!-- Contact specific fields here (email, phone, address)... -->
                                    <div class="form-group mb-3">
                                        <label for="description" class="form-label">Description:</label>
                                        <input type="text" class="form-control" id="description" name="description" value="${account.description || ''}">
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
                                        <label>Address:</label>
                                        <textarea class="form-control" id="address" name="address">${account.address || ''}</textarea>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Collapsible Group for Notes Details -->
                        <div class="accordion-item theme-container">
                            <h2 class="accordion-header theme-container" id="headingNotes">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseNotes" aria-expanded="false" aria-controls="collapseNotes">
                                    Notes and Custom Fields
                                </button>
                            </h2>
                            <div id="collapseNotes" class="accordion-collapse collapse" aria-labelledby="headingNotes" data-bs-parent="#accordionAccount">
                                <div class="accordion-body">
                                    <div class="mb-3">
                                        <label for="dueAt" class="form-label">Due At:</label>
                                        <input type="date" class="form-control" id="dueAt" name="due_at" value="${account.due_at_short || ''}" pattern="\\d{4}-\\d{2}-\\d{2}">
                                        <div class="form-text">Please select due date.</div>
                                    </div>
                                    <div class="form-group mb-3">
                                        <label for="notes" class="form-label">Notes:</label>
                                        <textarea class="form-control" id="notes" name="notes" rows="5">${account.notes || ''}</textarea>
                                    </div>
                                    <!-- Custom Fields for Edit -->
                                    <h5>Custom Fields:</h5>
                                    <div class="form-group mb-3" id="customFieldsEdit">
                                    </div>
                                    <button class="btn btn-info mb-3" type="button" onclick="addCustomField()">+ Add Custom Field</button>
                                </div>
                            </div>
                        </div>
                    </div>                    
    `;

    document.getElementById('password').value = account.password || '';
    const customFieldsContainer = document.getElementById('customFieldsEdit');
    if (account.form_fields) {
        for (const [key, value] of Object.entries(account.form_fields)) {
            const rowDiv = buildCustomField(key, value);
            customFieldsContainer.appendChild(rowDiv);
        }
    }

    const accountKind = document.getElementById('accountKind').value;
    const editCategory = document.getElementById('editCategory').value;
    if (accountKind === 'Contacts' || editCategory === 'Contacts') {
        const contactCollapse = new bootstrap.Collapse(document.getElementById('collapseContact'), {
            toggle: true
        });
    } else if (accountKind === 'Notes' || accountKind === 'Custom' || editCategory === 'Notes' || editCategory === 'Custom') {
        const notesCollapse = new bootstrap.Collapse(document.getElementById('collapseNotes'), {
            toggle: true
        });
    } else if (accountKind === 'Logins' || editCategory === 'Logins') {
        const loginCollapse = new bootstrap.Collapse(document.getElementById('collapseLogin'), {
            toggle: true
        });
    }

    const editModal = new bootstrap.Modal(document.getElementById('editAccountModal'));
    await editModal.show();
}

function expandAccordionSection(sectionId) {
    const collapseSection = document.getElementById(sectionId);
    const accordionButton = collapseSection.previousElementSibling.querySelector('.accordion-button');

    collapseSection.classList.add('show');
    accordionButton.setAttribute('aria-expanded', 'true');
    accordionButton.classList.remove('collapsed');
}

function buildCustomField(name, value) {
    const customFieldsContainer = document.getElementById('customFieldsEdit');
    // Create row div
    const rowDiv = document.createElement('div');
    rowDiv.setAttribute("class", "theme-container");
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
    document.getElementById('shareVaultModalLabel').innerText = 'Share Vault';
    document.getElementById('shareVaultUserInput').pllaceholder = 'Enter username to share with';
    document.getElementById('shareVaultUserMessage').innerText = 'Type in username who will be able to access all accounts in this vault.';
    document.getElementById('shareVaultButton').innerText = 'Share';

    const viewModal = new bootstrap.Modal(document.getElementById('shareVaultModal'));
    await viewModal.show();
}

async function doFetch(path, headers) {
    const response = await fetch(path, headers);
    if (response.status === 401 || response.headers.get('X-Signin') === 'required') {
        window.location.href = '/ui/signin';
        const text = await response.text();
        throw new Error(`Signin required Status: ${response.status} ${response.statusText} ${text}`);
    }
    return response;
}

async function handleShareUnShareVault(vaultId) {
    const username = document.getElementById('shareVaultUserInput').value;
    const shareUnshare = document.getElementById('shareVaultButton').innerText === 'Share' ? 'share' : 'unshare';
    const response = await doFetch(`/ui/vaults/${vaultId}/${shareUnshare}?target_username=${username}`, {
        method: 'POST',
    });
    if (!response.ok) {
        if (response.status === 409) {
            alert(`You have already ${shareUnshare}d vault with the ${username}`);
        } else {
            const text = await response.text();
            alert(`Could not ${shareUnshare} vault: ${response.status} ${response.statusText} ${text}`);
        }
        return;
    }
    const viewModal = bootstrap.Modal.getInstance(document.getElementById('shareVaultModal'));
    await viewModal.hide();
    showToast(`${shareUnshare}d vault with the ${username}!`);
    return true; //await response.json();
}

async function unshareVault() {
    // Show modal
    document.getElementById('shareVaultModalLabel').innerText = 'Un-Share Vault';
    document.getElementById('shareVaultUserInput').pllaceholder = 'Enter username to unshare with';
    document.getElementById('shareVaultUserMessage').innerText = 'Type in username who will be removed from access to all accounts in this vault.';
    document.getElementById('shareVaultButton').innerText = 'UnShare';

    const viewModal = new bootstrap.Modal(document.getElementById('shareVaultModal'));
    await viewModal.show();
}

async function handleShareAccount(vaultId) {
    const shareAccountId = document.getElementById('shareAccountId').value;
    const username = document.getElementById('shareAccountUserInput').value;
    const response = await doFetch(`/ui/vaults/${vaultId}/accounts/${shareAccountId}/share?target_username=${username}`, {
        method: 'POST',
    });
    if (!response.ok) {
        const text = await response.text();
        alert(`Could not share account: ${response.status} ${response.statusText} ${text}`);
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
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
        const response = await doFetch(path, {
            method: 'POST',
            body: formData
        });
        if (!response.ok) {
            const text = await response.text();
            if (password) {
                alert(`Could not import accounts, please verify password: ${response.status} ${response.statusText} ${text}`);
            } else {
                alert(`Could not import accounts, please try again: ${response.status} ${response.statusText} ${text}`);
            }
            throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
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

async function handleExportAccounts(vaultId, kind) {
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
    const suffix = getAccountDisplayKind(kind).toLowerCase();
    const a = document.createElement('a');
    a.href = password ? `/ui/vaults/${vaultId}/accounts/export?password=${password}` : `/ui/vaults/${vaultId}/accounts/export`;
    a.download = password ? `exported_${suffix}s.encrypted_csv` : `exported_${suffix}s.csv`;
    a.click();
    const viewModal = bootstrap.Modal.getInstance(document.getElementById('exportAccountsModal'));
    await viewModal.hide();
}


async function deleteAccount(id) {
    if (confirm('Are you sure you want to delete this account?')) {
        try {
            const response = await doFetch(`/ui/accounts/${id}/delete`, {
                    method: 'DELETE'
                }
            );
            if (!response.ok) {
                const text = await response.text();
                alert(`Could not delete account ${response.status} ${response.statusText} ${text}`);
                throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
            } else {
                showToast('Data deleted successfully!', () => {
                    location.reload();
                });
            }
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
        location.reload();
    } catch (e) {
        console.error('Failed to update the account', e);
    }
}

async function changePassword() {
    const form = document.forms['changePasswordForm'];
    const formData = new FormData(form);
    const newPassword = document.getElementById('newPassword').value.trim();
    const confirmNewPassword = document.getElementById('confirmNewPassword').value.trim();
    if (newPassword !== confirmNewPassword) {
        alert("New password didn't match confirm password");
        return;
    }
    const response = await doFetch("/ui/users/change_password", {
        method: 'POST',
        body: formData,
    });
    if (!response.ok) {
        const text = await response.text();
        alert(`Could not change password: ${text}`);
        console.error(`HTTP error! Status: ${response.status} status ${response.statusText} ${text}`);
        return;
    }
    const viewModal = bootstrap.Modal.getInstance(document.getElementById('changePasswordModal'));
    await viewModal.hide();
    alert('Your password is changed and all data is now encrypted with new password so you will need to sign-in with new password!');
    window.location.href = '/ui/signin';
    return true;
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
    const response = await doFetch(`/ui/accounts/${id}`, {
        method: 'GET',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });
    if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
    }
    try {
        return await response.json();
    } catch (e) {
        location.reload();
    }
}

async function postData(path, data) {
    const response = await doFetch(path, {
        method: 'POST',
        body: data,
    });
    if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
    }
    return true; //await response.json();
}

async function initEventHandlers() {
    await initEventHandler(document.getElementById('shareVaultUserInput'));
    await initEventHandler(document.getElementById('shareAccountUserInput'));

    // Start checking the session 5 minutes after login
    setTimeout(() => {
        // Check session every minute
        sessionCheckInterval = setInterval(checkSession, 60000);
    }, 300000); // 300000 milliseconds = 5 minutes
}

async function autocompleteUsername(term) {
    if (term.length < 2) {
        return [];
    }
    const response = await doFetch(`/ui/users/autocomplete?term=${term}`);
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
        a.setAttribute("class", "autocomplete-items theme-container");
        inp.parentNode.appendChild(a);

        for (let i = 0; i < usernames.length; i++) {
            if (usernames[i].substr(0, val.length).toUpperCase() === val.toUpperCase()) {
                const b = document.createElement("DIV");
                b.setAttribute("class", "autocomplete-entry theme-container"); // Use theme-container
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

function buildGauge(riskGaugeCtx, data, score, chartType, lightMode) {
    return new Chart(riskGaugeCtx, {
        type: chartType,
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
            scales: {
                x: {
                    grid: {
                        color: !lightMode ? '#444' : '#ccc',
                    },
                    ticks: {
                        color: !lightMode ? '#fff' : '#000',
                    }
                },
                y: {
                    grid: {
                        color: !lightMode ? '#444' : '#ccc',
                    },
                    ticks: {
                        color: !lightMode ? '#fff' : '#000',
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: !lightMode ? '#fff' : '#000',
                    }
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
    const response = await doFetch(`/ui/password/schedule_password_analysis`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
    })
    if (response.ok) {
        showToast('Scheduled password analysis!');
    } else {
        const text = await response.text();
        alert(`Could not schedule password analysis: ${response.status} ${response.statusText} ${text}`);
    }
}

async function generatePassword() {
    const form = document.getElementById('passwordForm');
    const formData = new FormData(form);
    const queryParams = new URLSearchParams(formData).toString();

    const response = await doFetch(`/ui/password/generate?${queryParams}`, {
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

async function checkPassword() {
    const inputPassword = document.getElementById('inputPassword').value;

    const response = await doFetch(`/ui/password/${inputPassword}/compromised`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        },
    })
    const data = await response.json();
    const passwordCheckResult = document.getElementById('passwordCheckResult');
    let hibp = '';
    if (data.compromised) {
        hibp = '(The password was found in <a href="https://haveibeenpwned.com/">https://haveibeenpwned.com/</a> database.)';
    }
    passwordCheckResult.innerHTML = `
        <table class="table table-striped-columns">
        <tr>
            <td><strong>Password Compromised:</strong></td><td>${data.compromised} ${hibp}</td>
        </tr>
        <tr>
            <td><strong>Password Strength:</strong></td><td>${data.strength}</td>
        </tr>
        <tr>
            <td><strong>Password Entropy:</strong></td><td>${data.entropy}</td>
        </tr>
        <tr>
            <td><strong>Password Length:</strong></td><td>${data.length}</td>
        </tr>
        <tr>
            <td><strong>Uppercase:</strong></td><td>${data.uppercase}</td>
        </tr>
        <tr>
            <td><strong>Lowercase:</strong></td><td>${data.lowercase}</td>
        </tr>
        <tr>
            <td><strong>Digits:</strong></td><td>${data.digits}</td>
        </tr>
        <tr>
            <td><strong>Special Characters:</strong></td><td>${data.special_chars}</td>
        </tr>
        </table>`;
}

async function checkEmailUrl() {
    const inputEmailOrUrl = document.getElementById('inputEmailOrUrl').value;

    const response = await doFetch(`/ui/emails/${inputEmailOrUrl}/compromised`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        },
    })
    const data = await response.json();
    const emailCompromiseCheckResult = document.getElementById('emailCompromiseCheckResult');
    emailCompromiseCheckResult.innerHTML = `${data}`;
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

    const response = await doFetch(`/ui/categories/${name}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
    })
    if (!response.ok) {
        const text = await response.text();
        alert(`Could not add category ${response.status} ${response.statusText} ${text}`);
        throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
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
            const response = await doFetch(`/ui/categories/${name}/delete`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            if (!response.ok) {
                const text = await response.text();
                alert(`Could not delete category ${response.status} ${response.statusText} ${text}`);
                throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
            } else {
                showToast('Category deleted successfully!', () => {
                    location.reload();
                });
            }
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
    }, 500);
}

async function removeMFAKey(id) {
    if (confirm('Are you sure you want to delete multi-factor authentication key?')) {
        try {
            // Send the credentials to the server
            const response = await doFetch('/ui/webauthn/unregister?id=' + id, {
                method: 'POST'
            });
            if (response.ok) {
                showToast('removed multi-factor authentication key', () => {
                    location.reload();
                })
            } else {
                const text = await response.text();
                alert(`Could not remove MFA keys ${response.status} ${response.statusText} ${text}`);
                throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
            }
        } catch (error) {
            console.error('Error removing MFA key:', error);
        }
    }
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    let bytes = new Uint8Array(buffer);
    let len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64UrlToBase64(base64Url) {
    // Replace "-" with "+" and "_" with "/"
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    // Pad with "=" to make the length a multiple of 4 if necessary
    while (base64.length % 4) {
        base64 += '=';
    }
    return base64;
}

function base64UrlToArrayBuffer(base64url) {
    var padding = '='.repeat((4 - base64url.length % 4) % 4);
    var base64 = (base64url + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');

    var rawData = window.atob(base64);
    var outputArray = new Uint8Array(rawData.length);

    for (var i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray.buffer;
}

async function signinMFA(options) {
    try {
        if (!options) {
            // Fetch options for authentication from the server
            const response = await doFetch('/ui/webauthn/login_start');
            options = await response.json();
        }

        // Convert challenge from Base64URL to ArrayBuffer
        options.publicKey.challenge = base64UrlToArrayBuffer(options.publicKey.challenge);

        // Convert id from Base64URL to ArrayBuffer for each allowed credential
        if (options.publicKey.allowCredentials) {
            for (let cred of options.publicKey.allowCredentials) {
                cred.id = base64UrlToArrayBuffer(cred.id);
            }
        }

        // Request an assertion
        const assertion = await navigator.credentials.get(options);

        // Send the assertion to the server for verification
        let response = await doFetch('/ui/webauthn/login_finish', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(assertion)
        });
        if (response.ok) {
            showToast('Login successful.', () => {
                document.location = '/';
            })
        }
    } catch (err) {
        console.error('Error during authentication:', err);
    }
}

async function showRegisterMFAKey() {
    const editModal = new bootstrap.Modal(document.getElementById('addMfaKeyModal'));
    await editModal.show();
}

async function registerMFAKey() {
    const keyName = document.getElementById('mfaKeyName').value;
    try {
        let response = await doFetch('/ui/webauthn/register_start');
        let options = await response.json();

        // Convert challenge from Base64URL to Base64, then to Uint8Array
        const challengeBase64 = base64UrlToBase64(options.publicKey.challenge);
        options.publicKey.challenge = Uint8Array.from(atob(challengeBase64), c => c.charCodeAt(0));

        // Convert user ID from Base64URL to Base64, then to Uint8Array
        const userIdBase64 = base64UrlToBase64(options.publicKey.user.id);
        options.publicKey.user.id = Uint8Array.from(atob(userIdBase64), c => c.charCodeAt(0));

        //options.challenge = Uint8Array.from(atob(options.challenge), c => c.charCodeAt(0));
        //options.user.id = Uint8Array.from(atob(options.user.id), c => c.charCodeAt(0));

        // Convert each excludeCredentials id from Base64URL to ArrayBuffer
        if (options.publicKey.excludeCredentials) {
            for (let cred of options.publicKey.excludeCredentials) {
                cred.id = base64UrlToArrayBuffer(cred.id);
            }
        }

        // Create a new credential
        const newCredential = await navigator.credentials.create(options);

        // Prepare data to be sent to the server
        const credentialForServer = {
            id: newCredential.id,
            rawId: arrayBufferToBase64(newCredential.rawId),
            response: {
                attestationObject: arrayBufferToBase64(newCredential.response.attestationObject),
                clientDataJSON: arrayBufferToBase64(newCredential.response.clientDataJSON)
            },
            type: newCredential.type
        };

        // Send the new credential to the server for verification and storage
        response = await doFetch('/ui/webauthn/register_finish?name=' + keyName, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credentialForServer)
        });
        let savedKey = await response.json();
        const registerMFAKeyDiv = document.getElementById('registerMFAKeyDiv');

        registerMFAKeyDiv.innerHTML = `
        <div class="alert alert-success" role="alert">
            <h4 class="alert-heading">Multi-Factor Authentication Key Added</h4>
            <p>Your multi-factor authentication key has been successfully added. In case you encounter issues signing in with multi-factor authentication, please use the following recovery code:</p>
            <hr>
            <p class="mb-0"><strong>Recovery Code:</strong> <span id="recoveryCode">${savedKey.recovery_code}</span></p>
            <button type="button" class="btn btn-outline-warning" onclick="copyToClipboard('${savedKey.recovery_code}')">Copy to Clipboard</button>
            <p class="text-danger mt-2"><strong>Notice:</strong> This recovery code will not be displayed again. Please store it in a safe place.</p>
        </div>`;

        const registerMFAKeyButton = document.getElementById('registerMFAKeyButton');
        registerMFAKeyButton.innerText = 'Close';
        registerMFAKeyButton.onclick = function () {
            location.reload();
        };
    } catch (err) {
        console.trace();
        console.error('Error during registration:', err);
    }
}

async function showEditProfile() {
    const editModal = new bootstrap.Modal(document.getElementById('editProfileModal'));
    await editModal.show();
}

async function showAPIToken(id) {
    const tokenModal = new bootstrap.Modal(document.getElementById('tokenModal'));
    const tokenDisplay = document.getElementById('tokenDisplay');

    try {
        const response = await doFetch('/ui/api_token');
        const data = await response.json();
        tokenDisplay.textContent = data.token;
    } catch (error) {
        console.error('Error fetching token:', error);
        tokenDisplay.textContent = 'Failed to load token.';
    }
    await tokenModal.show();
}

function copyTokenToClipboard() {
    const tokenDisplay = document.getElementById('tokenDisplay').textContent;
    copyToClipboard(tokenDisplay);
}

async function showAddEditVault(vaultId, version, title, kind) {
    document.getElementById('vaultForm').reset();
    document.getElementById('vaultId').value = vaultId || '';
    document.getElementById('vaultVersion').value = version || 0;
    document.getElementById('vaultName').value = title || '';
    document.getElementById('vaultKind').value = kind || '';
    document.getElementById('saveVaultButton').onclick = function () {
        updateVaultDetails(vaultId, version);
    }
    const editModal = new bootstrap.Modal(document.getElementById('vaultModal'));
    await editModal.show();
}

async function updateVaultDetails(vaultId, version) {
    const form = document.getElementById('vaultForm');
    const formData = new FormData(form);

    const path = vaultId ? `/ui/vaults/${vaultId}/update` : '/ui/vaults';
    try {
        const response = await doFetch(path, {
            method: 'POST',
            body: formData,
        });
        if (response.ok) {
            showToast('Vault updated successfully!', () => {
                location.reload();
            });
        } else {
            const text = await response.text();
            throw new Error(`Failed to save the vault: ${response.status} ${response.statusText} ${text}`);
        }
    } catch (e) {
        console.error('Failed to save the vault', e);
    }
}

async function deleteVault(vaultId, title) {
    if (confirm(`Are you sure you want to delete '${title}' Vault?`)) {
        try {
            const response = await doFetch(`/ui/vaults/${vaultId}/delete`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                },
            })
            if (!response.ok) {
                const text = await response.text();
                alert(`Could not delete vault ${response.status} ${response.statusText} ${text}`);
                throw new Error(`HTTP error! Status: ${response.status} ${response.statusText} ${text}`);
            } else {
                showToast('Vault deleted successfully!', () => {
                    location.reload();
                });
            }
        } catch (e) {
            console.error('Failed to delete data', e);
        }
    }
}


async function checkSession() {
    try {
        const response = await doFetch('/ui/check_session');
        if (response.headers.get('X-Signin') === 'required') {
            window.location.href = '/ui/signin';
        }
    } catch (error) {
        console.error('Session check failed:', error);
        window.location.href = '/ui/signin';
    }
}

function resetIdleTimer() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(async () => {
        // User is considered idle after IDLE_TIME_LIMIT
        await checkSession();
    }, IDLE_TIME_LIMIT);
}

function initCheckSession() {
    resetIdleTimer();

    window.addEventListener('mousemove', resetIdleTimer, false);
    window.addEventListener('keydown', resetIdleTimer, false);
    window.addEventListener('scroll', resetIdleTimer, false);
    window.addEventListener('touchmove', resetIdleTimer, false);
}
