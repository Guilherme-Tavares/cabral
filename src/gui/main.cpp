#include <cstdio>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include "MainWindow.hpp"

namespace {

void onGlfwError(int code, const char* description) {
    std::fprintf(stderr, "cabral-gui: glfw error %d: %s\n", code, description);
}

} // namespace

int main() {
    glfwSetErrorCallback(onGlfwError);

    if (glfwInit() == GLFW_FALSE) {
        std::fprintf(stderr, "cabral-gui: could not initialise GLFW; is a display available?\n");
        return 1;
    }

    // GL 3.0 + GLSL 130: suficiente para o backend do ImGui e amplamente disponível,
    // inclusive na aceleração por software de uma máquina virtual.
    const char* glslVersion = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1100, 720, "cabral", nullptr, nullptr);
    if (window == nullptr) {
        std::fprintf(stderr, "cabral-gui: could not create a window\n");
        glfwTerminate();
        return 1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glslVersion);

    {
        // A janela vive dentro deste escopo para ser destruída antes do contexto ImGui.
        cabral::gui::MainWindow mainWindow;

        while (glfwWindowShouldClose(window) == GLFW_FALSE && !mainWindow.wantsToClose()) {
            glfwPollEvents();

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();

            mainWindow.draw();

            ImGui::Render();

            int width = 0;
            int height = 0;
            glfwGetFramebufferSize(window, &width, &height);
            glViewport(0, 0, width, height);
            glClearColor(0.09f, 0.09f, 0.11f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);

            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            glfwSwapBuffers(window);
        }
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
