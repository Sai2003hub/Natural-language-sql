"""
Database Indexing Script for Performance Optimization

Run this script once to create indexes on frequently queried columns.
This will significantly speed up SELECT queries.
"""

import mysql.connector
from config import DATABASE_CONFIG

def create_indexes():
    """Create indexes on common query columns."""
    try:
        conn = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = conn.cursor()
        
        print("🔧 Starting database indexing...")
        
        # Get list of all tables
        cursor.execute("SHOW TABLES")
        tables = [table[0] for table in cursor.fetchall()]
        
        for table in tables:
            print(f"\n📊 Analyzing table: {table}")
            
            # Get columns for this table
            cursor.execute(f"DESCRIBE {table}")
            columns = cursor.fetchall()
            
            for column in columns:
                column_name = column[0]
                column_type = column[1]
                column_key = column[2]  # PRI, UNI, MUL, or empty
                
                # Skip if already indexed (PRIMARY, UNIQUE, or MULTIPLE index)
                if column_key in ['PRI', 'UNI', 'MUL']:
                    print(f"  ✓ {column_name} already indexed (Key: {column_key})")
                    continue
                
                # Create index for commonly filtered columns
                # Typically: name, email, date fields, status fields, foreign keys
                should_index = False
                
                if any(keyword in column_name.lower() for keyword in ['name', 'email', 'date', 'status', 'type', 'id', 'code']):
                    should_index = True
                elif 'VARCHAR' in column_type or 'DATE' in column_type or 'INT' in column_type:
                    should_index = True
                
                if should_index:
                    try:
                        index_name = f"idx_{table}_{column_name}"
                        cursor.execute(f"CREATE INDEX {index_name} ON {table}({column_name})")
                        print(f"  ✅ Created index: {index_name}")
                    except mysql.connector.Error as e:
                        if "Duplicate key name" in str(e):
                            print(f"  ⚠️  Index already exists for {column_name}")
                        else:
                            print(f"  ❌ Failed to create index for {column_name}: {e}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("\n✅ Database indexing completed successfully!")
        print("📈 Your queries should now run faster!")
        
    except mysql.connector.Error as err:
        print(f"❌ Database error: {err}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def show_existing_indexes():
    """Display all existing indexes in the database."""
    try:
        conn = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = conn.cursor()
        
        print("\n📋 Existing Indexes:")
        print("=" * 80)
        
        cursor.execute("SHOW TABLES")
        tables = [table[0] for table in cursor.fetchall()]
        
        for table in tables:
            cursor.execute(f"SHOW INDEX FROM {table}")
            indexes = cursor.fetchall()
            
            if indexes:
                print(f"\n📊 Table: {table}")
                for index in indexes:
                    index_name = index[2]
                    column_name = index[4]
                    non_unique = index[1]
                    index_type = "UNIQUE" if non_unique == 0 else "INDEX"
                    print(f"  • {index_type}: {index_name} on column '{column_name}'")
        
        cursor.close()
        conn.close()
        
    except mysql.connector.Error as err:
        print(f"❌ Database error: {err}")

if __name__ == "__main__":
    print("🚀 Database Performance Optimizer")
    print("=" * 80)
    
    # Show existing indexes first
    show_existing_indexes()
    
    # Ask user if they want to create new indexes
    print("\n" + "=" * 80)
    response = input("\n❓ Do you want to create new indexes? (yes/no): ").lower()
    
    if response in ['yes', 'y']:
        create_indexes()
    else:
        print("⏭️  Skipping index creation.")
    
    print("\n" + "=" * 80)
    print("✅ Done!")