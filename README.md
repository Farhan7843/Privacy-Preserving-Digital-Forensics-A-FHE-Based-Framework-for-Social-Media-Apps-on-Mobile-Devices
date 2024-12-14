#Update your system: 
sudo apt update && sudo apt upgrade
#Install required tools:
sudo apt install build-essential g++ -y
#Install git:
		sudo apt install git -y
#Clone the SEAL repository:
		git clone https://github.com/microsoft/SEAL.git
		cd SEAL
#Create a build directory:
		mkdir build && cd build
#Configure the build: Use CMake to configure SEAL. For example:
		cmake -D CMAKE_BUILD_TYPE=Release ..
#Build HELib:
		make -j$(nproc)
#Install HELib (optional): If you want to install HELib system-wide:
		sudo make install
#Create and Run a Project Using SEAL
		1. Create a New Project
			The project is called my_seal_project:
			Create a directory for my project:
				mkdir ~/my_seal_project
				cd ~/my_seal_project
#Write a simple SEAL program (e.g., main.cpp) or update the cpp db file inside the project 
#Write the CmakeLists.txt file outside the build folder
#Inside the build folder
	Cmake ..
	Make
	./file_name (whatsappcsv)
NB: The file needed to be encrypted must be present on the path that is declared inside code.
