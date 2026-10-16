import subprocess

print("zipping...")
subprocess.run(["zip", "-R", "./output/sources.zip", "./output", "-i", "*.cpp"])
subprocess.run(["zip", "-R", "./output/assemblies.zip", "./output", "-i", "*.asm"])
subprocess.run(["zip", "-R", "./output/assemblies-and-sources.zip", "./output", "-i", "*.asm", "*.cpp"])
subprocess.run(["zip", "-R", "./output/datas.zip", "./output", "-i", "*.json"])
print("done")
