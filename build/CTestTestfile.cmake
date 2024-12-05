# CMake generated Testfile for 
# Source directory: E:/Nishan/Amir/project
# Build directory: E:/Nishan/Amir/project/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(MyTest "E:/Nishan/Amir/project/build/Debug/MyTest.exe")
  set_tests_properties(MyTest PROPERTIES  _BACKTRACE_TRIPLES "E:/Nishan/Amir/project/CMakeLists.txt;30;add_test;E:/Nishan/Amir/project/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(MyTest "E:/Nishan/Amir/project/build/Release/MyTest.exe")
  set_tests_properties(MyTest PROPERTIES  _BACKTRACE_TRIPLES "E:/Nishan/Amir/project/CMakeLists.txt;30;add_test;E:/Nishan/Amir/project/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(MyTest "E:/Nishan/Amir/project/build/MinSizeRel/MyTest.exe")
  set_tests_properties(MyTest PROPERTIES  _BACKTRACE_TRIPLES "E:/Nishan/Amir/project/CMakeLists.txt;30;add_test;E:/Nishan/Amir/project/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(MyTest "E:/Nishan/Amir/project/build/RelWithDebInfo/MyTest.exe")
  set_tests_properties(MyTest PROPERTIES  _BACKTRACE_TRIPLES "E:/Nishan/Amir/project/CMakeLists.txt;30;add_test;E:/Nishan/Amir/project/CMakeLists.txt;0;")
else()
  add_test(MyTest NOT_AVAILABLE)
endif()
subdirs("googletest")
