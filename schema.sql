CREATE TABLE sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    content TEXT NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'content-creator'))
);

CREATE TABLE user_sites (
    user_id INTEGER NOT NULL,
    site_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, site_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (site_id) REFERENCES sites(id)
);

CREATE TABLE pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    slug TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id),
    UNIQUE (site_id, slug)
);

CREATE TABLE elements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    position INTEGER NOT NULL,
    FOREIGN KEY (page_id) REFERENCES pages(id)
);

-- Insert sample data
INSERT INTO sites (name, domain, content) VALUES
('Site A', 'sitea.localhost', 'Welcome to Site A!'),
('Site B', 'siteb.localhost', 'Welcome to Site B!');

INSERT INTO users (username, password, role) VALUES
('admin1', '$2a$10$examplehashedpassword1234567890', 'admin'),
('creator1', '$2a$10$examplehashedpassword1234567890', 'content-creator');

INSERT INTO user_sites (user_id, site_id) VALUES
(1, 1),
(2, 1);

INSERT INTO pages (site_id, title, slug) VALUES
(1, 'Home', 'home'),
(1, 'About', 'about'),
(2, 'Home', 'home');

INSERT INTO elements (page_id, type, content, position) VALUES
(1, 'text', '{"text": "Welcome to Site A''s home page!"}', 1),
(1, 'image', '{"src": "/static/images/sitea.jpg", "alt": "Site A Image"}', 2),
(2, 'text', '{"text": "About Site A."}', 1),
(3, 'text', '{"text": "Welcome to Site B''s home page!"}', 1),
(3, 'button', '{"text": "Contact Us", "url": "/contact"}', 2);