pipeline {
    def app
    agent { dockerfile true }
        stage('Build docker') {
            app = docker.build("unicorn_tracer")
    }
}