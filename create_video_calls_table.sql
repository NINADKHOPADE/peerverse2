-- Video Calls Table
CREATE TABLE IF NOT EXISTS video_calls (
    id SERIAL PRIMARY KEY,
    mentee_id INTEGER NOT NULL REFERENCES users(id),
    mentor_id INTEGER NOT NULL REFERENCES users(id),
    channel_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    accepted_at TIMESTAMP,
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    duration_minutes INTEGER,
    CONSTRAINT valid_status CHECK (status IN ('pending', 'accepted', 'rejected', 'active', 'completed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_video_calls_mentor_id ON video_calls(mentor_id);
CREATE INDEX IF NOT EXISTS idx_video_calls_mentee_id ON video_calls(mentee_id);
CREATE INDEX IF NOT EXISTS idx_video_calls_status ON video_calls(status);