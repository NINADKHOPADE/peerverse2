-- Create mentee_favorites table for storing favorite mentors
CREATE TABLE IF NOT EXISTS mentee_favorites (
    id SERIAL PRIMARY KEY,
    mentee_id INTEGER NOT NULL,
    mentor_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mentee_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (mentor_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(mentee_id, mentor_id)
);

-- Create index for better performance
CREATE INDEX IF NOT EXISTS idx_mentee_favorites_mentee_id ON mentee_favorites(mentee_id);
CREATE INDEX IF NOT EXISTS idx_mentee_favorites_mentor_id ON mentee_favorites(mentor_id);