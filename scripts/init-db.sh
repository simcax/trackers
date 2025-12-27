#!/bin/bash

# Database initialization script for the trackers application
# This script provides a convenient wrapper around the Python initialization script

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Initialize the trackers database with a new user and schema.

OPTIONS:
    --sample-data    Create sample tracker data after initialization
    --force         Drop existing database and user if they exist
    --debug         Enable debug output
    --help          Show this help message

ENVIRONMENT VARIABLES:
    Required:
        DB_HOST         PostgreSQL server host (e.g., localhost)
        DB_USER         Database username to create (e.g., trackers_user)
        DB_PASSWORD     Password for the database user
        DB_NAME         Database name to create (e.g., trackers)
    
    Optional:
        POSTGRES_USER   PostgreSQL superuser (default: postgres)
        POSTGRES_PASSWORD PostgreSQL superuser password (default: postgres)

EXAMPLES:
    # Basic initialization
    $0
    
    # Initialize with sample data
    $0 --sample-data
    
    # Force recreation of existing database
    $0 --force --sample-data
    
    # Using environment variables
    DB_HOST=localhost DB_USER=myuser DB_PASSWORD=mypass DB_NAME=mydb $0

SETUP:
    1. Ensure PostgreSQL is running
    2. Set required environment variables (or create .env file)
    3. Run this script
    4. Update your application configuration
    5. Run tests to verify setup

EOF
}

# Function to check if PostgreSQL is running
check_postgres() {
    print_info "Checking if PostgreSQL is running..."
    
    if command -v pg_isready >/dev/null 2>&1; then
        if pg_isready -h "${DB_HOST:-localhost}" -p 5432 >/dev/null 2>&1; then
            print_success "PostgreSQL is running and accepting connections"
        else
            print_error "PostgreSQL is not accepting connections"
            print_info "Please start PostgreSQL and try again"
            exit 1
        fi
    else
        print_warning "pg_isready not found, skipping PostgreSQL check"
    fi
}

# Function to check environment variables
check_environment() {
    print_info "Checking environment variables..."
    
    local missing_vars=()
    
    if [[ -z "$DB_HOST" ]]; then missing_vars+=("DB_HOST"); fi
    if [[ -z "$DB_USER" ]]; then missing_vars+=("DB_USER"); fi
    if [[ -z "$DB_PASSWORD" ]]; then missing_vars+=("DB_PASSWORD"); fi
    if [[ -z "$DB_NAME" ]]; then missing_vars+=("DB_NAME"); fi
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_error "Missing required environment variables: ${missing_vars[*]}"
        echo
        print_info "You can either:"
        print_info "1. Set them as environment variables:"
        print_info "   export DB_HOST=localhost"
        print_info "   export DB_USER=trackers_user"
        print_info "   export DB_PASSWORD=your_password"
        print_info "   export DB_NAME=trackers"
        echo
        print_info "2. Create a .env file in the project root:"
        print_info "   cp .env.example .env"
        print_info "   # Edit .env with your values"
        echo
        exit 1
    fi
    
    print_success "Environment variables are set"
}

# Function to check Python dependencies
check_dependencies() {
    print_info "Checking Python dependencies..."
    
    if ! command -v python3 >/dev/null 2>&1; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check if we're in a virtual environment or have uv
    if command -v uv >/dev/null 2>&1; then
        print_info "Using uv to run the initialization script"
        PYTHON_CMD="uv run python"
    elif [[ -n "$VIRTUAL_ENV" ]]; then
        print_info "Using virtual environment: $VIRTUAL_ENV"
        PYTHON_CMD="python"
    else
        print_warning "No virtual environment detected"
        print_info "Consider using 'uv sync' or activating a virtual environment"
        PYTHON_CMD="python3"
    fi
}

# Main function
main() {
    # Ensure we're running from the project root
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local project_root="$(dirname "$script_dir")"
    
    print_info "Project root: $project_root"
    cd "$project_root" || {
        print_error "Failed to change to project root directory"
        exit 1
    }
    
    # Parse command line arguments
    local args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_usage
                exit 0
                ;;
            --sample-data|--force)
                args+=("$1")
                shift
                ;;
            --debug)
                set -x  # Enable debug mode
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_info "Starting database initialization..."
    echo
    
    # Load .env file if it exists
    if [[ -f ".env" ]]; then
        print_info "Loading environment variables from .env file"
        set -a  # Automatically export all variables
        source .env
        set +a
    fi
    
    # Run checks
    check_environment
    check_postgres
    check_dependencies
    
    echo
    print_info "Running Python initialization script..."
    
    # Verify the trackers module exists
    if [[ ! -d "trackers" ]]; then
        print_error "trackers module directory not found"
        print_info "Make sure you're running this script from the project root"
        exit 1
    fi
    
    # Run the Python script with the collected arguments
    if $PYTHON_CMD scripts/init-db.py "${args[@]}"; then
        echo
        print_success "Database initialization completed successfully!"
        echo
        print_info "You can now:"
        print_info "• Run tests: pytest"
        print_info "• Start the application: python main.py"
        print_info "• Connect to the database: psql -h $DB_HOST -U $DB_USER -d $DB_NAME"
    else
        echo
        print_error "Database initialization failed!"
        print_info "Check the error messages above for details"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"