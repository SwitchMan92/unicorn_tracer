node {
    checkout scm

    def customImage = docker.build("unicorn_tracer")

    customImage.inside {
        sh 'cd /var/unicorn_tracer'
        sh 'python -m unittest discover'
    }
}