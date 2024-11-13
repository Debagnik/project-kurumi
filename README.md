# Blog Site

Welcome to the **Blog Site** project. It is a simple webapp for small-startups to post their blogs, or news outlets for publishing news article 

## Features

- **User Authentication**
  - Sign up and login functionality using secure authentication.
  - Admins can disable or enable registration from evnvironment variable (Future plans has to move this feature to DB)
- **CRUD Operations**
  - Create, read, update, and delete blog posts.
  - proper access privilege for admin dashboard access
  - Markdown support in editor (In-future development)
- **Comments Section**
  - Users can comment on posts using disqus integration. (In-progress)
  - In future development will be saved to DB with DDoS protection
- **Responsive Design**
  - Accessible on both desktop and mobile devices.
  - A better UI development is in progress

## Technologies Used

- **Frontend**
  - HTML5, CSS3, JavaScript
- **Backend**
  - Node.js, Express.js
  - Database: MongoDB with Mongoose ODM

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Debagnik/Blog-Site.git
   ```
2. **Navigate to the project directory:**
   ```bash
   cd Blog-Site
   ```
3. **Install dependencies:**
   ```bash
   npm install
   ```
4. **Configure the environment variables:**
   - Create a `.env` file and add your MongoDB URI and any other required configurations as below.
     ```text
     MONGO_DB_URI=mongodb://username:password@host/blog #Required
     PORT=80 #Optonal, defaults to 5000
     ENABLE_REGISTRATION=true #defaults to false
     SEARCH_PAGANATION_LIMIT=10 #defaults to 10
     JWT_SECRET=your-default-jwt-secrets #Required
     SESSION_SECRET=your-secure-session-secret #Required
     NODE_ENV=dev-local #Defaults to dev-local use production in production scenario
     DEFAULT_POST_THUMBNAIL_LINK=/img/placeholder.webp #Keep it as is
     ```
5. **Start the application:**
   ```bash
   npm start
   ```
   or on Developer machine
   ```bash
   npm run dev
   ```

## Usage

- Access the application at `http://localhost:5000` in your web browser.
- Register a new account or log in with existing credentials.
- Create new blog posts, edit them, or delete if necessary.
- View and comment on other users' posts.

## Contributing

I welcome all enhancement and bugfix and issue reports. Please feel free to contibute
If you are interested in contributing to this project:
1. Fork the repository
2. Create a branch from the latest release.
3. Submit your pull request against the release branch.
4. Please also label your PR (enhancement for adding features, Bugfix for for bug fixing PRs)
PS: You contribution will be reviewed by codeRabbitAi and it's tone of review will be bit harsh I made it to sound like a Tsundere, but it sometimes come of rude. 

## License

This project is licensed under the MIT License.

## Contact

For any questions or concerns, you can reach out at [info@debagnik.in](mailto:info@debagnik.in).

This project is powered by [@CoderabbitAi](coderabbit.ai) and [Tabnine AI](https://www.tabnine.com/)
