/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/

#include "trace.h"

/* Lists the supported APIs by reading from a markdown file under a specific title */
void list_api()
{
    const char *file_path = API_LIST_MD_PATH; // Path to the markdown file
    FILE *file = fopen(file_path, "r"); // Open the file for reading
    if (file == NULL) {
        fprintf(stderr, "Error opening %s\n", file_path); // Output error message with the file path
        return;
    }

    char line[MAX_LINE_LENGTH];
    int in_section = 0;  // Flag to track if we are in the desired section
    const char *section_title = "# Gazelle Supported POSIX Interface List";  // The section we are looking for

    /* Read the file line by line */
    while (fgets(line, sizeof(line), file) != NULL) {
        // Optionally, check for reading errors
        if (ferror(file)) {
            fprintf(stderr, "Error reading from %s\n", file_path); // Output error message
            break;
        }

        // Check if the line is the section title
        if (strncmp(line, section_title, strlen(section_title)) == 0) {
            in_section = 1;  // Start printing the section content
            continue;        // Skip the section title line itself
        }

        // If we are in the section, print the content until we encounter a new section or an empty line
        if (in_section) {
            // Stop printing if we encounter a new title or an empty line
            if (line[0] == '\n' || line[0] == '#') {
                break;  // Exit the section
            }
            printf("%s", line);  // Print the current line
        }
    }

    // Close the file and handle any potential errors
    if (fclose(file) != 0) {
        fprintf(stderr, "Error closing %s\n", file_path);   // Output error message with the file path on closing error
    }
}

