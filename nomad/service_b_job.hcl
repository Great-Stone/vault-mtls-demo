job "mtls-service-b" {
  datacenters = ["dc1"]

  type = "service"

  group "service" {
    count = 1

    network {
	    port "https" {
        static = 8433
      }
    }
    
    vault {
      namespace = ""
      policies = ["pki"]
      change_mode = "noop"
    }

    task "python-task" {
      driver = "raw_exec"

      config {
        command = "local/start.sh"
      }

// // 로컬의 파일을 사용하는 경우
//       template {
//         data = <<EOH
// #!/bin/bash
// cp -R /경로/mtls-pki/python_service_b python_service_b
// cd python_service_b
// pip install requests flask
// python main.py
//       EOH
// 				destination = "local/start.sh"
//       }

      artifact {
        source      = "https://github.com/Great-Stone/vault-mtls-demo/releases/download/0.1.0/python_service_b.zip"
        destination = "python_service_b"
      }
      template {
        data = <<EOH
#!/bin/bash
cd python_service_b
pip install requests flask
python main.py
      EOH
				destination = "local/start.sh"
      }

      template {
        data = <<EOH
{{- /* ca-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-b.example.com" "ttl=2m" }}
{{ .Data.issuing_ca }}{{ end }}
      EOH
				destination = "/cert/ca.crt"
				change_mode = "noop"
      }
      template {
        data = <<EOH
{{- /* cert-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-b.example.com" "ttl=2m" }}
{{ .Data.certificate }}{{ end }}
      EOH
				destination = "/cert/service-b.crt"
				change_mode = "restart"
      }
      template {
        data = <<EOH
{{- /* key-a.tpl */ -}}
{{ with secret "pki/issue/example-dot-com" "common_name=service-b.example.com" "ttl=2m" }}
{{ .Data.private_key }}{{ end }}
      EOH
				destination = "/cert/service-b.key"
				change_mode = "noop"
      }
    }
  }
}