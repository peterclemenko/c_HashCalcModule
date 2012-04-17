/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file HashCalcModule.cpp 
 * C++ Framework module that calculates hash values of file content. */
// System includes
#include <windows.h>
#include <sstream>

// Framework includes
#include "TskModuleDev.h"

// Poco includes
#include "Poco/MD5Engine.h"
#include "Poco/SHA1Engine.h"
#include "Poco/DigestStream.h"

// We process the file 8k at a time
static const uint32_t FILE_BUFFER_SIZE = 8192;

// Flags that indicate which hashes to calculate
static bool calculateMD5 = false;
static bool calculateSHA1 = false;

// Names that will be used to store data in blackboard
static const std::string MD5_NAME("MD5");
static const std::string SHA1_NAME("SHA1");

extern "C" 
{
    /**
     * Module initialization function. Takes a string as input that allows
     * arguments to be passed into the module.
     * @param arguments Tells the module which hashes to calculate. Valid values
     * are "MD5", "SHA1" or the empty string which will result in both hashes
     * being calculated. Hash names can be in any order and have space or comma
     * separating them. 
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(std::string& arguments)
    {
        // If the argument string is empty we calculate both hashes.
        if (arguments.empty()) {
            calculateMD5 = true;
            calculateSHA1 = true;
        }

        // If the argument string contains "MD5" we calculate an MD5 hash.
        if (arguments.find(MD5_NAME) != std::string::npos)
            calculateMD5 = true;

        // If the argument string contains "SHA1" we calculate a SHA1 hash.
        if (arguments.find(SHA1_NAME) != std::string::npos)
            calculateSHA1 = true;

        // If neither hash is to be calculated it means that the arguments
        // passed to the module were incorrect. We log an error message
        // through the framework logging facility.
        if (!calculateMD5 && !calculateSHA1) {
            std::wstringstream msg;
            msg << L"Invalid arguments passed to hash module: " << arguments.c_str();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Hash the file and post the results to the database. 
     * @param pFile A pointer to a file to be processed.
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile) {
        if (pFile == NULL) {
            LOGERROR(L"HashCalcModule: passed NULL file pointer.");
            return TskModule::FAIL;
        }

        try {
            if (!pFile->exists()) {
                std::wstringstream msg;
                msg << L"HashCalcModule: File to be analyzed does not exist: " << pFile->getPath().c_str();
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }

            // Open file.
            pFile->open();

            // Initialize hash engine
            Poco::MD5Engine md5;
            Poco::DigestOutputStream md5dos(md5);

            Poco::SHA1Engine sha1;
            Poco::DigestOutputStream sha1dos(sha1);

            char buffer[FILE_BUFFER_SIZE];
            int bytesRead = 0;
            bool read = false;

            // Read file content into buffer and write it to the DigestOutputStream.
            do {
                bytesRead = pFile->read(buffer, FILE_BUFFER_SIZE);
                if (bytesRead > 0)
                    read = true;

                if (calculateMD5)
                    md5dos.write(buffer, bytesRead);
                if (calculateSHA1)
                    sha1dos.write(buffer, bytesRead);
            } while (bytesRead > 0);

            if (!read) {
                // Close the digest stream
                md5dos.close();
                sha1dos.close();

                // Close file.
                pFile->close();
                return TskModule::OK;
            }

            if (calculateMD5) {
                md5dos.flush();
                const Poco::DigestEngine::Digest md5Digest = md5.digest();
                std::string hashStr = Poco::DigestEngine::digestToHex(md5Digest);
                pFile->setHash(TskImgDB::MD5, hashStr);
            }

            if (calculateSHA1) {
                sha1dos.flush();
                const Poco::DigestEngine::Digest sha1Digest = sha1.digest();
                std::string hashStr = Poco::DigestEngine::digestToHex(sha1Digest);
                pFile->setHash(TskImgDB::SHA1, hashStr);
            }

            // Close the digest stream
            md5dos.close();
            sha1dos.close();

            // Close file.
            pFile->close();
        }
        catch (TskException& tskEx)
        {
            std::wstringstream msg;
            msg << L"HashCalcModule - Caught framework exception: " << tskEx.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"HashCalcModule - Caught exception: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}

