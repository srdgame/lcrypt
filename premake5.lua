-- A solution
workspace "lua-crypt"
	configurations { "Debug", "Release"}
	location "build"

project "lcrypt"
	kind "SharedLib"
	language "C++"
	location "build"
	targetprefix ""
	targetdir "bin/%{cfg.buildcfg}"

	includedirs { 
		"/usr/include/lua5.3",
		--"/home/cch/mycode/skynet/3rd/lua/",
		".",
	}
	files { 
		"src/**.c",
	}

	buildoptions { '-Wall', '-Wextra', '-Werror' }

	--libdirs { "../../bin" }
	links { "pthread" }
	--linkoptions { "" }

	filter "configurations:Debug"
		defines { "DEBUG" }
		symbols "On"

	filter "configurations:Release"
		defines { "NDEBUG" }
		optimize "On"
