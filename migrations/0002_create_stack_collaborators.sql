CREATE TABLE stack_collaborators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stack_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (stack_id) REFERENCES stacks(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(stack_id, user_id)
);