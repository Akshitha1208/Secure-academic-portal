// Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// State management
let currentUser = null;
let authToken = null;

// ==================== UTILITY FUNCTIONS ====================

function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    const container = document.querySelector('.container');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    document.getElementById(pageId).classList.add('active');
}

function updateNavigation() {
    const navLinks = document.getElementById('nav-links');
    
    if (currentUser) {
        navLinks.innerHTML = `
            <span>Welcome, ${currentUser.full_name || currentUser.username}</span>
            <a href="#" onclick="logout()">Logout</a>
        `;
    } else {
        navLinks.innerHTML = '';
    }
}

// ==================== AUTHENTICATION ====================

function showLoginForm() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('otp-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'none';
}

function showRegisterForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('otp-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
}

async function handleRegister(event) {
    event.preventDefault();
    
    const fullName = document.getElementById('reg-fullname').value;
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;
    const role = document.getElementById('reg-role').value;
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username,
                email,
                password,
                role,
                full_name: fullName
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert('Registration successful! Please login.', 'success');
            showLoginForm();
            event.target.reset();
        } else {
            showAlert(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

async function handleLogin(event) {
    event.preventDefault();
    
    const identifier = document.getElementById('login-identifier').value;
    const password = document.getElementById('login-password').value;
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                identifier,
                password
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Show OTP form
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('otp-form').style.display = 'block';
            document.getElementById('otp-user-id').value = data.user_id;
            
            // For demonstration, show the OTP
            if (data.otp) {
                showAlert(`OTP sent! (Demo: ${data.otp})`, 'info');
            } else {
                showAlert('OTP sent to your email!', 'success');
            }
        } else {
            showAlert(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

async function handleOTPVerification(event) {
    event.preventDefault();
    
    const userId = document.getElementById('otp-user-id').value;
    const otp = document.getElementById('otp-code').value;
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/verify-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                user_id: userId,
                otp
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.token;
            currentUser = data.user;
            
            // Store in session
            sessionStorage.setItem('token', authToken);
            sessionStorage.setItem('user', JSON.stringify(currentUser));
            
            showAlert('Login successful!', 'success');
            showDashboard();
        } else {
            showAlert(data.error || 'OTP verification failed', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

function logout() {
    currentUser = null;
    authToken = null;
    sessionStorage.clear();
    showPage('auth-page');
    updateNavigation();
    showLoginForm();
}

// ==================== DASHBOARD ====================

function showDashboard() {
    showPage('dashboard-page');
    updateNavigation();
    
    // Update user display
    document.getElementById('user-name-display').textContent = currentUser.full_name || currentUser.username;
    const roleBadge = document.getElementById('user-role-badge');
    roleBadge.textContent = currentUser.role.toUpperCase();
    roleBadge.className = `badge badge-${currentUser.role}`;
    
    // Load role-specific dashboard
    const dashboardContent = document.getElementById('dashboard-content');
    dashboardContent.innerHTML = '';
    
    if (currentUser.role === 'student') {
        document.getElementById('dashboard-title').textContent = 'Student Dashboard';
        const studentDash = document.getElementById('student-dashboard').cloneNode(true);
        studentDash.style.display = 'block';
        dashboardContent.appendChild(studentDash);
        loadStudentProjects();
    } else if (currentUser.role === 'faculty') {
        document.getElementById('dashboard-title').textContent = 'Faculty Dashboard';
        const facultyDash = document.getElementById('faculty-dashboard').cloneNode(true);
        facultyDash.style.display = 'block';
        dashboardContent.appendChild(facultyDash);
        loadFacultyProjects();
    } else if (currentUser.role === 'admin') {
        document.getElementById('dashboard-title').textContent = 'Admin Dashboard';
        const adminDash = document.getElementById('admin-dashboard').cloneNode(true);
        adminDash.style.display = 'block';
        dashboardContent.appendChild(adminDash);
        loadAdminDashboard();
    }
}

// ==================== STUDENT FUNCTIONS ====================

async function handleUpload(event) {
    event.preventDefault();
    
    const title = document.getElementById('project-title').value;
    const description = document.getElementById('project-description').value;
    const fileInput = document.getElementById('project-file');
    const file = fileInput.files[0];
    
    if (!file) {
        showAlert('Please select a file', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', title);
    formData.append('description', description);
    
    try {
        const response = await fetch(`${API_BASE_URL}/projects/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`
            },
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert('Project uploaded and encrypted successfully!', 'success');
            event.target.reset();
            loadStudentProjects();
        } else {
            showAlert(data.error || 'Upload failed', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

async function loadStudentProjects() {
    try {
        const response = await fetch(`${API_BASE_URL}/projects`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayProjects(data.projects, 'student-projects', true);
        } else {
            showAlert(data.error || 'Failed to load projects', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

// ==================== FACULTY FUNCTIONS ====================

async function loadFacultyProjects() {
    try {
        const response = await fetch(`${API_BASE_URL}/projects`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayProjects(data.projects, 'faculty-projects', false);
        } else {
            showAlert(data.error || 'Failed to load projects', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

async function verifyProject(projectId) {
    const status = prompt('Enter verification status (verified/rejected):', 'verified');
    if (!status) return;
    
    const comments = prompt('Enter comments:', '');
    
    try {
        const response = await fetch(`${API_BASE_URL}/projects/${projectId}/verify`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status, comments })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert('Project verified and digitally signed!', 'success');
            loadFacultyProjects();
        } else {
            showAlert(data.error || 'Verification failed', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

// ==================== ADMIN FUNCTIONS ====================

async function loadAdminDashboard() {
    try {
        // Load users
        const usersResponse = await fetch(`${API_BASE_URL}/users`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (usersResponse.ok) {
            const usersData = await usersResponse.json();
            displayUsers(usersData.users);
            document.getElementById('total-users').textContent = usersData.users.length;
        }
        
        // Load projects
        const projectsResponse = await fetch(`${API_BASE_URL}/projects`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (projectsResponse.ok) {
            const projectsData = await projectsResponse.json();
            displayProjects(projectsData.projects, 'admin-projects', false);
            document.getElementById('total-projects').textContent = projectsData.projects.length;
            
            const verifiedCount = projectsData.projects.filter(p => p.status === 'verified').length;
            document.getElementById('total-verifications').textContent = verifiedCount;
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

function displayUsers(users) {
    const usersTable = document.getElementById('admin-users');
    
    let html = '<div class="user-row"><strong>Username</strong><strong>Email</strong><strong>Role</strong><strong>Actions</strong></div>';
    
    users.forEach(user => {
        html += `
            <div class="user-row">
                <div>${user.username}</div>
                <div>${user.email}</div>
                <div><span class="badge badge-${user.role}">${user.role}</span></div>
                <div>
                    <button class="btn btn-secondary" onclick="changeUserRole(${user.id}, '${user.role}')">
                        Change Role
                    </button>
                </div>
            </div>
        `;
    });
    
    usersTable.innerHTML = html;
}

async function changeUserRole(userId, currentRole) {
    const newRole = prompt(`Change role for user (current: ${currentRole})\nEnter: student, faculty, or admin`, currentRole);
    
    if (!newRole || !['student', 'faculty', 'admin'].includes(newRole)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/users/${userId}/role`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ role: newRole })
        });
        
        if (response.ok) {
            showAlert('User role updated successfully!', 'success');
            loadAdminDashboard();
        } else {
            const data = await response.json();
            showAlert(data.error || 'Failed to update role', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

async function viewACLPolicy() {
    try {
        const response = await fetch(`${API_BASE_URL}/system/acl`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            const aclDisplay = document.getElementById('acl-display');
            aclDisplay.innerHTML = `<pre>${JSON.stringify(data.acl_policy, null, 2)}</pre>`;
            aclDisplay.style.display = 'block';
        } else {
            showAlert(data.error || 'Failed to load ACL policy', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

// ==================== SHARED FUNCTIONS ====================

function displayProjects(projects, containerId, isStudent) {
    const container = document.getElementById(containerId);
    
    if (projects.length === 0) {
        container.innerHTML = '<p>No projects found.</p>';
        return;
    }
    
    let html = '';
    
    projects.forEach(project => {
        const statusClass = `status-${project.status}`;
        
        html += `
            <div class="project-card">
                <div class="project-header">
                    <div>
                        <div class="project-title">${project.title}</div>
                        ${!isStudent ? `<div class="project-info">By: ${project.student_name || project.username}</div>` : ''}
                    </div>
                    <span class="project-status ${statusClass}">${project.status}</span>
                </div>
                <div class="project-info">
                    ${project.description || 'No description'}
                </div>
                <div class="project-info">
                    File: ${project.file_name}<br>
                    Hash: ${project.file_hash.substring(0, 16)}...<br>
                    Uploaded: ${new Date(project.created_at).toLocaleDateString()}
                </div>
                <div class="project-actions">
                    <button class="btn btn-primary" onclick="downloadProject(${project.id})">
                        🔓 Download
                    </button>
                    <button class="btn btn-secondary" onclick="viewProjectDetails(${project.id})">
                        View Details
                    </button>
                    ${!isStudent && currentUser.role === 'faculty' ? `
                        <button class="btn btn-success" onclick="verifyProject(${project.id})">
                            ✓ Verify & Sign
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

async function downloadProject(projectId) {
    try {
        const response = await fetch(`${API_BASE_URL}/projects/${projectId}/download`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'project-file';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            showAlert('Project downloaded and decrypted!', 'success');
        } else {
            const data = await response.json();
            showAlert(data.error || 'Download failed', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

async function viewProjectDetails(projectId) {
    try {
        const projectResponse = await fetch(`${API_BASE_URL}/projects/${projectId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const verificationsResponse = await fetch(`${API_BASE_URL}/projects/${projectId}/verifications`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (projectResponse.ok && verificationsResponse.ok) {
            const projectData = await projectResponse.json();
            const verificationsData = await verificationsResponse.json();
            
            showProjectModal(projectData.project, verificationsData.verifications);
        } else {
            showAlert('Failed to load project details', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

function showProjectModal(project, verifications) {
    const modal = document.getElementById('project-modal');
    const modalBody = document.getElementById('modal-body');
    
    let html = `
        <h2>${project.title}</h2>
        <div class="project-info">
            <strong>Student:</strong> ${project.student_name || project.username}<br>
            <strong>Status:</strong> ${project.status}<br>
            <strong>File:</strong> ${project.file_name}<br>
            <strong>Description:</strong> ${project.description || 'N/A'}<br>
            <strong>File Hash (SHA-256):</strong> <code>${project.file_hash}</code><br>
            <strong>Uploaded:</strong> ${new Date(project.created_at).toLocaleString()}
        </div>
        
        <h3>Verifications</h3>
    `;
    
    if (verifications.length === 0) {
        html += '<p>No verifications yet.</p>';
    } else {
        verifications.forEach(v => {
            html += `
                <div class="verification-details">
                    <div class="verification-item">
                        <strong>Faculty:</strong>
                        <span>${v.faculty_name || v.faculty_username}</span>
                    </div>
                    <div class="verification-item">
                        <strong>Status:</strong>
                        <span>${v.status}</span>
                    </div>
                    <div class="verification-item">
                        <strong>Comments:</strong>
                        <span>${v.comments || 'No comments'}</span>
                    </div>
                    <div class="verification-item">
                        <strong>Digital Signature:</strong>
                        <span style="font-family: monospace; font-size: 0.8em; word-break: break-all;">
                            ${v.signature.substring(0, 100)}...
                        </span>
                    </div>
                    <div class="verification-item">
                        <strong>Verified At:</strong>
                        <span>${new Date(v.created_at).toLocaleString()}</span>
                    </div>
                    <button class="btn btn-secondary" onclick="verifySignature(${v.id})">
                        Verify Digital Signature
                    </button>
                </div>
            `;
        });
    }
    
    modalBody.innerHTML = html;
    modal.classList.add('active');
}

async function verifySignature(verificationId) {
    try {
        const response = await fetch(`${API_BASE_URL}/verifications/${verificationId}/verify-signature`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            if (data.is_valid) {
                showAlert('✓ Digital signature is VALID! Integrity verified.', 'success');
            } else {
                showAlert('✗ Digital signature is INVALID! File may be tampered.', 'error');
            }
        } else {
            showAlert(data.error || 'Failed to verify signature', 'error');
        }
    } catch (error) {
        showAlert('Network error: ' + error.message, 'error');
    }
}

function closeModal() {
    document.getElementById('project-modal').classList.remove('active');
}

// ==================== INITIALIZATION ====================

window.addEventListener('DOMContentLoaded', () => {
    // Check for existing session
    const storedToken = sessionStorage.getItem('token');
    const storedUser = sessionStorage.getItem('user');
    
    if (storedToken && storedUser) {
        authToken = storedToken;
        currentUser = JSON.parse(storedUser);
        showDashboard();
    } else {
        showPage('auth-page');
    }
    
    // Close modal on outside click
    window.onclick = function(event) {
        const modal = document.getElementById('project-modal');
        if (event.target === modal) {
            closeModal();
        }
    };
});
