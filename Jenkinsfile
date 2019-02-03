pipeline {
    def app
    agent { dockerfile true }
    stages {
        stage('Build docker') {
            app = docker.build("unicorn_tracer")
        }
    }
}