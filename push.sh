go mod tidy
tinygo build -o main.wasm -scheduler=none -target=wasi -gc=custom -tags="custommalloc nottinygc_finalizer" ./
cp ./main.wasm ../wasm-docker/
cd ../wasm-docker
docker build -t registry.cn-hangzhou.aliyuncs.com/jingze/wasm-plugin:1.0.0 -f Dockerfile .
image_id=$(docker images --filter=reference="registry.cn-hangzhou.aliyuncs.com/jingze/wasm-plugin:1.0.0" --format "{{.ID}}")
docker tag ${image_id} registry.cn-hangzhou.aliyuncs.com/jingze/wasm-plugin:1.0.0
docker push registry.cn-hangzhou.aliyuncs.com/jingze/wasm-plugin:1.0.0
