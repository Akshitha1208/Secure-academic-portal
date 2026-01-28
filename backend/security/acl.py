"""
Access Control List (ACL) Manager
Implements role-based access control

SUBJECTS (Roles):
1. Student
2. Faculty
3. Admin

OBJECTS (Resources):
1. Projects
2. Verification Records
3. User Data

ACCESS RIGHTS:
- create (C)
- read (R)
- update (U)
- delete (D)
"""


class ACLManager:
    """Manages access control policies"""
    
    def __init__(self):
        """
        Initialize ACL with permission matrix
        
        Permission Matrix:
        ----------------------------------------------------------------
        Role      | Projects        | Verification    | User Data
        ----------------------------------------------------------------
        Student   | CR-- (own only) | R--- (own only) | R--- (own only)
        Faculty   | -R-- (all)      | CR-- (all)      | R--- (all)
        Admin     | CRUD (all)      | CRUD (all)      | CRUD (all)
        ----------------------------------------------------------------
        
        C = Create, R = Read, U = Update, D = Delete
        """
        self.acl_policy = {
            'student': {
                'projects': {
                    'create': True,   # Students can upload projects
                    'read': 'own',    # Students can only read their own projects
                    'update': 'own',  # Students can update their own projects
                    'delete': 'own'   # Students can delete their own projects
                },
                'verification_records': {
                    'create': False,  # Students cannot create verifications
                    'read': 'own',    # Students can view verifications of their projects
                    'update': False,  # Students cannot update verifications
                    'delete': False   # Students cannot delete verifications
                },
                'user_data': {
                    'create': False,  # Handled by registration
                    'read': 'own',    # Students can view their own profile
                    'update': 'own',  # Students can update their own profile
                    'delete': False   # Students cannot delete users
                }
            },
            'faculty': {
                'projects': {
                    'create': False,  # Faculty don't upload projects
                    'read': True,     # Faculty can view all projects
                    'update': False,  # Faculty cannot update projects
                    'delete': False   # Faculty cannot delete projects
                },
                'verification_records': {
                    'create': True,   # Faculty can verify projects
                    'read': True,     # Faculty can view all verifications
                    'update': True,   # Faculty can update their verifications
                    'delete': 'own'   # Faculty can delete their own verifications
                },
                'user_data': {
                    'create': False,  # Handled by registration
                    'read': True,     # Faculty can view user information
                    'update': False,  # Faculty cannot update users
                    'delete': False   # Faculty cannot delete users
                }
            },
            'admin': {
                'projects': {
                    'create': True,   # Admin has full access
                    'read': True,     # Admin can view all projects
                    'update': True,   # Admin can update projects
                    'delete': True    # Admin can delete projects
                },
                'verification_records': {
                    'create': True,   # Admin has full access
                    'read': True,     # Admin can view all verifications
                    'update': True,   # Admin can update verifications
                    'delete': True    # Admin can delete verifications
                },
                'user_data': {
                    'create': True,   # Admin can create users
                    'read': True,     # Admin can view all users
                    'update': True,   # Admin can update user roles
                    'delete': True    # Admin can delete users
                }
            }
        }
    
    def check_permission(self, role, action, resource):
        """
        Check if a role has permission to perform action on resource
        
        Args:
            role (str): User role (student, faculty, admin)
            action (str): Action to perform (create, read, update, delete)
            resource (str): Resource type (projects, verification_records, user_data)
            
        Returns:
            bool or str: True if allowed, 'own' if only for owned resources, False if denied
        """
        role = role.lower()
        action = action.lower()
        resource = resource.lower()
        
        # Validate inputs
        if role not in self.acl_policy:
            return False
        
        if resource not in self.acl_policy[role]:
            return False
        
        if action not in self.acl_policy[role][resource]:
            return False
        
        # Get permission
        permission = self.acl_policy[role][resource][action]
        
        return permission
    
    def get_policy(self):
        """
        Get the complete ACL policy
        
        Returns:
            dict: Complete ACL policy matrix
        """
        return self.acl_policy
    
    def get_user_permissions(self, role):
        """
        Get all permissions for a specific role
        
        Args:
            role (str): User role
            
        Returns:
            dict: Permissions for the role
        """
        role = role.lower()
        
        if role not in self.acl_policy:
            return {}
        
        return self.acl_policy[role]
    
    def add_permission(self, role, resource, action, allowed):
        """
        Add or update a permission
        
        Args:
            role (str): User role
            resource (str): Resource type
            action (str): Action type
            allowed (bool or str): Permission value
        """
        role = role.lower()
        resource = resource.lower()
        action = action.lower()
        
        if role not in self.acl_policy:
            self.acl_policy[role] = {}
        
        if resource not in self.acl_policy[role]:
            self.acl_policy[role][resource] = {}
        
        self.acl_policy[role][resource][action] = allowed
    
    def remove_permission(self, role, resource, action):
        """
        Remove a permission
        
        Args:
            role (str): User role
            resource (str): Resource type
            action (str): Action type
        """
        role = role.lower()
        resource = resource.lower()
        action = action.lower()
        
        if (role in self.acl_policy and 
            resource in self.acl_policy[role] and 
            action in self.acl_policy[role][resource]):
            del self.acl_policy[role][resource][action]
    
    def print_policy_matrix(self):
        """
        Print ACL policy in a readable format
        """
        print("\n" + "="*70)
        print("ACCESS CONTROL LIST (ACL) POLICY MATRIX")
        print("="*70)
        
        for role, resources in self.acl_policy.items():
            print(f"\n{role.upper()}:")
            print("-" * 70)
            
            for resource, actions in resources.items():
                print(f"  {resource}:")
                for action, permission in actions.items():
                    perm_str = str(permission).ljust(10)
                    print(f"    - {action}: {perm_str}")
        
        print("\n" + "="*70)
        print("Legend: True = Allowed, False = Denied, 'own' = Only owned resources")
        print("="*70 + "\n")


# Demonstration
if __name__ == "__main__":
    acl = ACLManager()
    acl.print_policy_matrix()
    
    # Test permissions
    print("\nTest Cases:")
    print(f"Can student create project? {acl.check_permission('student', 'create', 'projects')}")
    print(f"Can student read all projects? {acl.check_permission('student', 'read', 'projects')}")
    print(f"Can faculty verify projects? {acl.check_permission('faculty', 'create', 'verification_records')}")
    print(f"Can admin manage users? {acl.check_permission('admin', 'update', 'user_data')}")
