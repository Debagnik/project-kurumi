# Project Walnut (クルミ)

![Walnut_Lycoris-Recoil](public/img/kurumi.png)
[Walnut the mascot](https://lycoris-recoil.fandom.com/wiki/Kurumi)

Welcome to the **Project Walnut** project. It is a simple webapp for small-startups to post their blogs, or news outlets for publishing news article 

## Features

- **User Authentication**
  - Sign up and login functionality using secure authentication. For editors, moderators and site admins(web master)
  - Admins can disable or enable registration from site configurations
- **CRUD Operations**
  - Create, read, update, and delete blog posts.
  - proper access privilege for admin dashboard access
  - Webmaster portal for maintaining site settings and global site config
  - Markdown support in editors
- **Comments Section**
  - Comments section
  - Comments posting
  - Comments to be turned off sitewide from global config
  - Cloudflare Turnstile intregation for Bot attacks.
- **AI Integration**
  - LLM Based Paraphrazer/Summarizer/TL;DR generation (In Beta Stage)
- **Responsive Design**
  - Accessible on both desktop and mobile devices.
  - Accessible Dark/light UI for better reading experience (planned future scope)

## Technologies Used

- **Frontend**
  - CSS3, JavaScript, EJS
- **Services**
  - Node.js, Express.js
  - Database: MongoDB with Mongoose ODM
- **Backend**
  - Database: MongoDB with Mongoose ODM

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Debagnik/project-walnut.git
   ```
2. **Navigate to the project directory:**
   ```bash
   cd project-walnut
   ```
3. **Install dependencies:**
   ```bash
   npm install
   ```
4. **Configure the environment variables:**
   - Create a `.env` file and add your MongoDB URI and any other required configurations as below.
     ```text
      ### Must have to run this application
      MONGO_DB_URI=mongodb+srv://<test>@blog-site.hx49l.mongodb.net/<test> #Required
      PORT= #Optonal, defaults to 5000
      JWT_SECRET=your-default-jwt-secrets #Required
      SESSION_SECRET=your-secure-session-secret #Required
      NODE_ENV=dev-local #Defaults to dev-local use production in production scenario
      DEFAULT_POST_THUMBNAIL_LINK=/img/placeholder.webp #Keep it as is
      
      MAX_TITLE_LENGTH=100 
      MAX_DESCRIPTION_LENGTH=10000
      MAX_BODY_LENGTH=100000
      DUMMY_STRING=Error Message: The Tracking URL is not valid check with Web Master

      ## Enviroment variable Required if LLM Based Blog Summary generator is enabled.
      OPENROUTER_API_KEY=<Your OpenRouter API Key> #Optional OpenAI or OpenRouter Secret Key for AI Integration
      SYSTEM_PROMPT=You are an assistant editor that summarizes the blogpost body in  #Required if AI Integration is enabled from webmaster.
      USER_PROMPT=Summarize the following blog written in Markdown (Absolutely limit your response to #Required if AI Integration is enabled from webmaster.
      USER_PROMPT_2=characters) do not add character/word count in the response. #Required if AI Integration is enabled from webmaster.
-     LLM_MODEL=<The Model name of your choice> #Required if AI Integration is enabled from webmaster.
+     LLM_MODEL=<The Model name supported by OpenRouter, e.g., "anthropic/claude-3-opus"> #Required if AI Integration is enabled from webmaster.
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

## Acknowledgments
This project is enhanced by:
- [CodeRabbitAI](https://coderabbit.ai) - Code review assistance
- [Tabnine AI](https://www.tabnine.com/) - Code completion support (Discontinued)
- [ChatGPT](https://chatgpt.com) - Google and Stack overflow alternative
