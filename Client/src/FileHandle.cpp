//
// Created by גאי ברנשטיין on 20/09/2024.
//
#include "FileHandle.h"

FileHandle::FileHandle() : _isOpen(false), _isWriteMode(false) {}

FileHandle::~FileHandle()
{
    close();
}

/**
 * Open a file for read/write. Create folders in filepath if do not exist.
 * Relative paths not supported!
 */
bool FileHandle::open(const std::string& filepath, bool write)
{
    if (filepath.empty())
        return false;
    close(); // Close any previously open streams
    _isWriteMode = write;

    try
    {
        // Create parent directories if they don't exist
        const auto parent = boost::filesystem::path(filepath).parent_path();
        if (!parent.empty())
        {
            (void)create_directories(parent);
        }

        // Open the appropriate stream
        if (_isWriteMode)
        {
            _outStream.open(filepath, std::ios::binary | std::ios::out);
            _isOpen = _outStream.is_open();
        }
        else
        {
            _inStream.open(filepath, std::ios::binary | std::ios::in);
            _isOpen = _inStream.is_open();
        }
    }
    catch (...)
    {
        _isOpen = false;
    }
    return _isOpen;
}


/**
 * Close file stream.
 */
void FileHandle::close()
{
    if(!_isOpen)
        return;
    if (_isWriteMode) {
        _outStream.close();
    }
    else {
        _inStream.close();
    }
    _isOpen = false;
}

/**
 * Read a single line from fs to line.
 */
bool FileHandle::readLine(std::string& line)
{
    if (!_isOpen || _isWriteMode){
        close();
        return false;
    }

    try
    {
        if (!std::getline(_inStream, line) || line.empty())
        {
            close();
            return false;
        }
        return true;
    }
    catch (...)
    {
        close();
        return false;
    }
}

/**
 * Read a chunk of data from fs to line. Indicate if that is all the file.
 */
bool FileHandle::readChunk(std::string &chunk, csize_t chunkSize, bool &eof) {
    if (!isOpen() || isWriteMode()) {
        close();
        return false;
    }

    try {
        chunk.clear(); // reset chunk
        std::vector<char> buffer(chunkSize, 0); // allocate and initialize memory for reading

        // Clear the error state before reading
        _inStream.clear();

        _inStream.read(buffer.data(), chunkSize);
        std::streamsize bytesRead = _inStream.gcount();

        // Handle for other stream errors
        if (bytesRead == 0) {
            close();
            eof = true;
            return false;
        }

        chunk.append(buffer.data(), bytesRead);
        eof = true; // we got to the end of the file

        // still dont close yet
        return true;
    }
    catch (const std::exception& e) {
        close();
        return false;
    }
    catch (...)
    {
        close();
        return false;
    }
}

/**
 * Write data to fs.
 */
bool FileHandle::write(const std::string &data) {
    if (!_isOpen || !_isWriteMode || data.empty())
        return false;
    try
    {

        _outStream.write(data.c_str(), static_cast<std::streamsize>(data.size()));
        return _outStream.good();
    }
    catch (...)
    {
        return false;
    }
}

/**
 * Write client name to fs.
 */
bool FileHandle::write(const ClientName& clientName)
{
    if (!_isOpen || !_isWriteMode)
        return false;
    try
    {
        // Find the position of the first null character
        auto pos = std::find(clientName.begin(), clientName.end(), '\0');
        csize_t length = std::distance(clientName.begin(), pos);

        // Write-only up to the null character (or the entire array if no null is found)
        _outStream.write(reinterpret_cast<const char*>(clientName.data()), length);
        return _outStream.good();
    }
    catch (...)
    {
        return false;
    }
}
/**
 * Write a single line- client name - and new line char
 */

bool FileHandle::writeLine(const ClientName& clientName)
{
    if (!write(clientName))
        return false;
    return write("\n");
}


/**
 * Write a single string and append an end line character.
 */
bool FileHandle::writeLine(const std::string &line)
{
    return write(line + '\n');
}

/**
 * Get the size of the fs, handle large files.
 */
size_t FileHandle::size() {
    if (!isOpen())
        return 0;
    try
    {
        if(isWriteMode()){
            const auto cur = _outStream. tellp();
            _outStream.seekp(0, std::ios::end);
            const auto size = _outStream.tellp();
            _outStream.seekp(cur);  // restore position
            return (size > 0 && size <= UINT32_MAX) ? static_cast<size_t>(size) : 0;
        } else {
            const auto cur = _inStream.tellg();
            _inStream.seekg(0, std::ios::end);
            const auto size = _inStream.tellg();
            _inStream.seekg(cur);  // restore position
            return (size > 0 && size <= UINT32_MAX) ? static_cast<size_t>(size) : 0;
        }
    }
    catch (...)
    {
        return 0;
    }
}



