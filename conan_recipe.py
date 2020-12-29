from conans import CMake
from conans import ConanFile
from conans.errors import ConanException

import os
import shutil

class CryptoboxConan(ConanFile):
	# custom properties for usage by this specific recipe's code, not by the Conan SDK

	_repository_name = 'cryptobox'

	_repository_url = 'git@github.com:theodor96/{name}.git'.format(name=_repository_name)

	_build_subfolder = 'build'

	_conan_cmake_generator_file = 'conanbuildinfo.cmake'

	_cmake = None

	# Conan properties, used by the Conan SDK

	name = 'cryptobox'

	description = 'Cryptobox is a library that acts like a poor man\'s HSM'

	version = '0.1'

	author = 'Theodor Serbana <theodor.serbana96@gmail.com>'

	license = 'GNU LGPL'

	url = 'https://github.com/theodor96/cryptobox'

	settings = 'os', 'compiler', 'build_type', 'arch'

	generators = 'cmake'

	def source(self):
		self.output.info('Cloning {name} from: {url}'.format(name=self._repository_name, url=self._repository_url))
		
		# try to clone the repository.
		# if there's any failure, let it propagate, but show a pretty error message
		#
		try:
			self.run('git clone . {url}'.format(url=self._repository_url))
		except ConanException:
			self.output.info('Unable to clone {name}. See errors below.'.format(name=self._repository_name))
			raise

	def get_cmake(self):
		if self._cmake:
			return self._cmake

		# also make sure Conan created the generator file successfully
		#
		if not os.path.exists(self._conan_cmake_generator_file):
			raise ConanException('Conan CMake dependencies file {file} does not exist'.format(file=self._conan_cmake_generator_file))

		# create the build subfolder inside the source tree root and put the generator file in it
		#
		if not os.path.exists(self._build_subfolder):
			os.makedirs(self._build_subfolder)

		shutil.move(self._conan_cmake_generator_file, self._build_subfolder)

		cmake = CMake(self)

		# finally call cmake and update the instance property for next usages
		#
		cmake.configure(build_folder=self._build_subfolder)
		self._cmake = cmake

		return cmake

	def build(self):
		cmake = self.get_cmake()
		cmake.build()

	def package(self):
		# then call the CMake install target for the build artefacts
		#
		cmake = self.get_cmake()
		cmake.install()

	def package_info(self):
		self.cpp_info.libs = ['libcryptobox.so']
