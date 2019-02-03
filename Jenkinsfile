pipeline {
    agent { docker { image 'unicorn_tracer' } }
    stages {
        stage('Checkout repository') {
            steps {
                checkout scm
            }
        }
    }
}